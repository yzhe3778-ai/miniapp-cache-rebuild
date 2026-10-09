#!/usr/bin/env node
'use strict';
// Analyze verified local files only. Target code is parsed, never evaluated by JavaScript.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const VERSION = '1.1.0';
const LIMITS = { fileBytes: 32 * 1024 * 1024, files: 20000, depth: 60, steps: 50000, items: 10000, string: 2 * 1024 * 1024, records: 15000 };
const MARK = Symbol('unresolved');
const unresolved = (reason, expression = '') => ({ [MARK]: true, reason, expression });
const isUnknown = x => !!(x && x[MARK]);
function containsUnknown(value, seen = new Set()) { if (isUnknown(value)) return true; if (!value || typeof value !== 'object' || seen.has(value)) return false; seen.add(value); return Object.values(value).some(item => containsUnknown(item, seen)); }
const sha = x => crypto.createHash('sha256').update(x).digest('hex');
const sourceCode = n => generate(n, { comments: false, compact: true }).code;
const keyOf = n => n && (n.name ?? n.value);
function lstatIfPresent(filename) { try { return fs.lstatSync(filename); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } }
const forbidden = k => ['__proto__', 'prototype', 'constructor'].includes(String(k));
function serial(value, depth = 0) {
  if (depth > LIMITS.depth) return { unresolved: 'serialization-depth-limit' };
  if (isUnknown(value)) return { unresolved: value.reason, expression: value.expression };
  if (value && value.helper) return { staticHelper: value.helper };
  if (typeof value === 'undefined') return { unresolved: 'undefined' };
  if (Array.isArray(value)) return value.map(v => serial(v, depth + 1));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, serial(v, depth + 1)]));
  if (typeof value === 'number' && !Number.isFinite(value)) return { unresolved: 'non-finite-number' };
  return value;
}
function safeRelative(input) {
  if (typeof input !== 'string' || !input || input.includes('\\') || input.includes('\0') || path.posix.isAbsolute(input) || /^[A-Za-z]:/.test(input)) throw Error('Expected a safe relative path');
  const parts = input.split('/');
  if (parts.some(p => !p || p === '.' || p === '..' || forbidden(p))) throw Error('Unsafe relative path component');
  return input;
}
function confined(root, relative, existing = true) {
  safeRelative(relative);
  const target = path.resolve(root, relative);
  if (!target.startsWith(root + path.sep)) throw Error('Path escapes evidence root');
  let cursor = root;
  for (const item of relative.split('/')) {
    cursor = path.join(cursor, item);
    if (lstatIfPresent(cursor)?.isSymbolicLink()) throw Error('Symlink in evidence path');
  }
  if (existing && !fs.existsSync(target)) throw Error('Missing evidence file');
  return target;
}
function assertNoSymlinks(absolute) {
  let cursor = path.parse(absolute).root;
  for (const part of absolute.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    if (lstatIfPresent(cursor)?.isSymbolicLink() && !(process.platform === 'darwin' && ['/tmp', '/var', '/etc'].includes(cursor))) throw Error('Symlink in input/output root');
  }
}
function provenance(p, origin) {
  return { ...origin, line: p.node.loc?.start.line ?? null, column: p.node.loc?.start.column ?? null, charOffset: p.node.start ?? null };
}
function enclosingModule(p) {
  const ancestor = p.findParent(q => q.isCallExpression() && q.node.callee.type === 'Identifier' && q.node.callee.name === 'define' && q.node.arguments[0]?.type === 'StringLiteral');
  return ancestor?.node.arguments[0].value ?? null;
}
function behaviorCall(p, origin) {
  const callee = sourceCode(p.node.callee);
  const families = [
    ['storage', /^wx\.(?:getStorage|setStorage|removeStorage|clearStorage)(?:Sync)?$/],
    ['export', /^wx\.(?:downloadFile|saveFile|saveImageToPhotosAlbum|saveVideoToPhotosAlbum|openDocument|canvasToTempFilePath)$/],
    ['navigation', /^wx\.(?:navigateTo|redirectTo|switchTab|reLaunch|navigateBack)$/],
    ['state', /(?:^|\.)setData$/],
  ];
  const kind = families.find(([, pattern]) => pattern.test(callee))?.[0];
  if (!kind) return null;
  const owner = p.getFunctionParent();
  const parent = owner?.parentPath;
  const name = owner?.node.id?.name ??
    (owner?.isObjectMethod() || owner?.isClassMethod() ? keyOf(owner.node.key) : null) ??
    (parent?.isObjectProperty() ? keyOf(parent.node.key) : null) ??
    (parent?.isVariableDeclarator() ? parent.node.id?.name : null) ?? null;
  return { kind, callee, owner: typeof name === 'string' ? name : null,
    module: enclosingModule(p), source: provenance(p, origin), evidence: 'static-call-syntax',
    limitation: 'Callee spelling does not prove receiver identity, reachability or runtime success.' };
}
function conditional(p) {
  for (let q = p.parentPath; q; q = q.parentPath) {
    if (q.isFunction()) return false;
    if (q.isForStatement() && q.node.init && (p.node === q.node.init || p.findParent(ancestor => ancestor.node === q.node.init))) continue;
    if (q.isIfStatement() || q.isSwitchCase() || q.isWhileStatement() || q.isForStatement() || q.isForOfStatement() || q.isForInStatement() || q.isDoWhileStatement()) return true;
  }
  return false;
}
function literalKey(node, computed, evaluate) { return computed ? evaluate(node) : keyOf(node); }
class StaticEvaluator {
  constructor() { this.values = new Map(); this.resolving = new Set(); }
  binding(name, scope) { return scope.getBinding(name) ?? null; }
  evaluate(node, scope, overrides = new Map(), budget = { steps: 0 }, depth = 0) {
    if (!node) return unresolved('missing-expression');
    if (++budget.steps > LIMITS.steps || depth > LIMITS.depth) return unresolved('evaluation-limit');
    const rec = n => this.evaluate(n, scope, overrides, budget, depth + 1);
    const fail = reason => unresolved(reason, sourceCode(node).slice(0, 1000));
    const t = node.type;
    if (['StringLiteral', 'NumericLiteral', 'BooleanLiteral'].includes(t)) return node.value;
    if (t === 'NullLiteral') return null;
    if (t === 'Identifier') {
      const binding = this.binding(node.name, scope);
      if (!binding) return fail('unbound-identifier');
      if (overrides.has(binding)) return overrides.get(binding);
      if (this.values.has(binding)) return this.values.get(binding);
      if (this.resolving.has(binding)) return fail('cyclic-binding');
      if (!binding.path.isVariableDeclarator() || !binding.path.node.init) return fail('dynamic-binding');
      this.resolving.add(binding);
      const value = this.evaluate(binding.path.node.init, binding.path.scope, overrides, budget, depth + 1);
      this.resolving.delete(binding);
      return value;
    }
    if (t === 'ArrayExpression') {
      const result = [];
      for (const item of node.elements) {
        if (!item) result.push(null);
        else if (item.type === 'SpreadElement') {
          const value = rec(item.argument); if (!Array.isArray(value)) return fail('unresolved-array-spread'); result.push(...value);
        } else result.push(rec(item));
        if (result.length > LIMITS.items) return fail('collection-limit');
      }
      return result;
    }
    if (t === 'ObjectExpression') {
      const result = Object.create(null);
      for (const item of node.properties) {
        if (item.type === 'SpreadElement') { const value = rec(item.argument); if (!value || typeof value !== 'object' || isUnknown(value) || Array.isArray(value)) return fail('unresolved-object-spread'); Object.assign(result, value); continue; }
        if (item.type !== 'ObjectProperty') { result[keyOf(item.key) || '<method>'] = unresolved('function-or-method'); continue; }
        const key = literalKey(item.key, item.computed, rec);
        if (isUnknown(key) || forbidden(key)) return fail('unsafe-object-key');
        result[key] = rec(item.value);
      }
      return result;
    }
    if (t === 'MemberExpression' || t === 'OptionalMemberExpression') {
      const object = rec(node.object), key = literalKey(node.property, node.computed, rec);
      if (isUnknown(object) || isUnknown(key) || forbidden(key)) return fail('unresolved-member');
      if (Array.isArray(object) && key === 'length') return object.length;
      if (typeof object === 'string' && key === 'length') return object.length;
      if (object != null && Object.hasOwn(Object(object), key)) return object[key];
      return fail('missing-static-member');
    }
    if (t === 'UnaryExpression') {
      const v = rec(node.argument); if (isUnknown(v) || (v && typeof v === 'object')) return fail('unresolved-unary');
      if (node.operator === '-') return -v;
      if (node.operator === '+') return +v;
      if (node.operator === '!') return !v;
      if (node.operator === '~') return ~v;
      if (node.operator === 'void') return undefined;
      if (node.operator === 'typeof') return typeof v;
      return fail('unsupported-unary');
    }
    if (t === 'BinaryExpression' || t === 'LogicalExpression') {
      const a = rec(node.left); if (isUnknown(a) || (a && typeof a === 'object')) return fail('unresolved-binary-left');
      if (node.operator === '&&') return a ? rec(node.right) : a;
      if (node.operator === '||') return a ? a : rec(node.right);
      if (node.operator === '??') return a == null ? rec(node.right) : a;
      const b = rec(node.right); if (isUnknown(b) || (b && typeof b === 'object')) return fail('unresolved-binary-right');
      let result;
      switch (node.operator) {
        case '+': result = a + b; break; case '-': result = a - b; break; case '*': result = a * b; break; case '/': result = a / b; break; case '%': result = a % b; break;
        case '===': result = a === b; break; case '!==': result = a !== b; break;
        case '==': result = a == b; break; case '!=': result = a != b; break;
        case '<': result = a < b; break; case '>': result = a > b; break; case '<=': result = a <= b; break; case '>=': result = a >= b; break;
        default: return fail('unsupported-binary');
      }
      return typeof result === 'string' && result.length > LIMITS.string ? fail('string-limit') : result;
    }
    if (t === 'ConditionalExpression') { const test = rec(node.test); return isUnknown(test) ? fail('unresolved-condition') : rec(test ? node.consequent : node.alternate); }
    if (t === 'TemplateLiteral') {
      let text = node.quasis[0].value.cooked ?? node.quasis[0].value.raw;
      for (let i = 0; i < node.expressions.length; i++) { const v = rec(node.expressions[i]); if (isUnknown(v) || (v && typeof v === 'object')) return fail('unresolved-template'); text += String(v) + (node.quasis[i + 1].value.cooked ?? node.quasis[i + 1].value.raw); if (text.length > LIMITS.string) return fail('string-limit'); }
      return text;
    }
    if (t === 'SequenceExpression') return rec(node.expressions.at(-1));
    if (t === 'CallExpression' || t === 'OptionalCallExpression') {
      const callee = node.callee;
      if (callee.type === 'Identifier' && callee.name === 'require' && node.arguments[0]?.type === 'StringLiteral' && /(?:^|\/)toConsumableArray$/.test(node.arguments[0].value)) {
        const binding = scope.getBinding('require');
        const factory = binding?.path.findParent(p => p.isFunction());
        const recognized = !binding || (binding.kind === 'param' && factory?.parentPath.isCallExpression() && keyOf(factory.parentPath.node.callee) === 'define');
        return recognized ? { helper: 'toConsumableArray' } : fail('shadowed-require-not-static-helper');
      }
      if (callee.type === 'Identifier') {
        const value = rec(callee);
        if (value?.helper === 'toConsumableArray') { const a = rec(node.arguments[0]); return Array.isArray(a) ? [...a] : fail('helper-requires-static-array'); }
        return fail('call-not-allowlisted');
      }
      if (callee.type !== 'MemberExpression') return fail('call-not-allowlisted');
      const method = literalKey(callee.property, callee.computed, rec);
      if (callee.object.type === 'Identifier' && callee.object.name === 'Object' && method === 'freeze' && !scope.getBinding('Object')) return rec(node.arguments[0]);
      const value = rec(callee.object);
      if (isUnknown(value)) return fail('unresolved-call-receiver');
      if (['map', 'flatMap'].includes(method) && Array.isArray(value)) {
        const callback = node.arguments[0];
        if (!callback || !['ArrowFunctionExpression', 'FunctionExpression'].includes(callback.type) || callback.async || callback.generator || callback.params.some(n => n.type !== 'Identifier')) return fail('unsupported-static-callback');
        let returned = callback.body;
        if (returned.type === 'BlockStatement') {
          if (returned.body.length !== 1 || returned.body[0].type !== 'ReturnStatement') {
            if (method === 'map') return value.map(() => unresolved('map-shape-only-callback-not-evaluated', sourceCode(callback).slice(0, 1000)));
            return fail('impure-static-callback');
          }
          returned = returned.body[0].argument;
        }
        if (!returned) return fail('missing-callback-result');
        // Babel scopes are available by the callback's own path, registered at traversal start.
        const cbScope = this.scopes.get(callback);
        if (!cbScope) return fail('missing-callback-scope');
        const result = [];
        for (let i = 0; i < value.length; i++) {
          const mapped = new Map(overrides);
          callback.params.forEach((param, n) => mapped.set(cbScope.getBinding(param.name), n === 0 ? value[i] : n === 1 ? i : value));
          const item = this.evaluate(returned, cbScope, mapped, budget, depth + 1);
          if (isUnknown(item)) return item;
          if (method === 'flatMap' && Array.isArray(item)) result.push(...item); else result.push(item);
          if (result.length > LIMITS.items) return fail('collection-limit');
        }
        return result;
      }
      const args = [];
      for (const arg of node.arguments) { const v = rec(arg.type === 'SpreadElement' ? arg.argument : arg); if (isUnknown(v)) return fail('unresolved-call-argument'); if (arg.type === 'SpreadElement') { if (!Array.isArray(v)) return fail('unresolved-call-spread'); args.push(...v); } else args.push(v); }
      if (method === 'concat' && (typeof value === 'string' || Array.isArray(value))) { if (typeof value === 'string' && args.some(a => a && typeof a === 'object')) return fail('unresolved-string-concat'); const result = value.concat(...args); if (result.length > (Array.isArray(result) ? LIMITS.items : LIMITS.string)) return fail('result-limit'); return result; }
      if (method === 'join' && Array.isArray(value) && args.length <= 1 && value.every(x => !isUnknown(x) && (x == null || ['string', 'number', 'boolean'].includes(typeof x)))) { const result = value.join(...args); return result.length > LIMITS.string ? fail('string-limit') : result; }
      return fail('call-not-allowlisted');
    }
    return fail('unsupported-expression-' + t);
  }
  initScopes(ast) { this.scopes = new WeakMap(); traverse(ast, { Function: p => { this.scopes.set(p.node, p.scope); } }); }
  set(binding, value) { if (binding) this.values.set(binding, value); }
  mutate(p) {
    const node = p.node;
    let receiver, operation, operands;
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
      const callee = node.callee;
      if (keyOf(callee.property) === 'push') { receiver = callee.object; operation = 'push'; operands = node.arguments; }
      else if (keyOf(callee.property) === 'apply' && callee.object.type === 'MemberExpression' && keyOf(callee.object.property) === 'push') { receiver = node.arguments[0]; operation = 'push.apply'; operands = [node.arguments[1]]; }
    }
    if (!receiver || receiver.type !== 'Identifier') return null;
    const binding = this.binding(receiver.name, p.scope);
    if (!binding) return null;
    const owner = binding.scope.getFunctionParent();
    if (p.scope.getFunctionParent() !== owner || conditional(p)) { this.set(binding, unresolved('conditional-or-cross-function-mutation', sourceCode(node))); return binding; }
    const existing = this.evaluate(receiver, p.scope), args = [];
    if (!Array.isArray(existing)) return null;
    for (const operand of operands) { const v = this.evaluate(operand.type === 'SpreadElement' ? operand.argument : operand, p.scope); if (operation === 'push.apply' || operand.type === 'SpreadElement') { if (!Array.isArray(v)) { this.set(binding, unresolved('unresolved-mutation')); return binding; } args.push(...v); } else args.push(v); }
    const value = [...existing, ...args]; this.set(binding, value.length > LIMITS.items ? unresolved('collection-limit') : value); return binding;
  }
}
function analyzeFile(code, origin, collections) {
  let ast;
  try { ast = parser.parse(code, { sourceType: 'unambiguous', errorRecovery: false }); }
  catch (error) { collections.warnings.push({ code: 'parse-failed', source: origin, message: error.message }); return; }
  const evaluator = new StaticEvaluator(); evaluator.initScopes(ast);
  const recordBindings = new Map();
  function record(binding, p, reason) {
    if (!binding) return;
    const value = evaluator.values.get(binding);
    if (value === undefined) return;
    if (isUnknown(value)) {
      const previous = recordBindings.get(binding);
      if (previous) { previous.value = serial(value); previous.finalLength = null; previous.valueCompleteness = 'unresolved'; previous.history.push({ reason, ...provenance(p, {}), length: null, unresolved: value.reason }); }
      return;
    }
    if (!Array.isArray(value) && !(value && typeof value === 'object') && !(typeof value === 'string' && (value.length >= 120 || /^https?:\/\//.test(value)))) return;
    const item = recordBindings.get(binding) ?? { name: binding.identifier.name, module: enclosingModule(p), source: provenance(binding.path, origin), evaluation: 'bounded-static-dataflow', history: [] };
    item.value = serial(value); item.finalLength = Array.isArray(value) ? value.length : null; item.valueCompleteness = containsUnknown(value) ? 'partial-static-value-or-array-shape; callbacks not executed' : 'fully-static-value';
    item.history.push({ reason, ...provenance(p, {}), length: Array.isArray(value) ? value.length : null });
    recordBindings.set(binding, item);
  }
  function inspectStrings(value, p, key = '', seen = new Set()) {
    if (isUnknown(value) || value == null) return;
    if (typeof value === 'string') {
      if (value.length > 60000) return;
      const prompted = /prompt|instruction|system|提示词|系统提示/i.test(key) || /提示词|system prompt|API.*契约|API.*接入|请在当前项目中接入/i.test(value);
      if (prompted) {
        const actual = value.length > 100 && /prompt|instruction|提示词/i.test(key);
        const purpose = /API|接口/.test(value) && /接入|契约|鉴权/.test(value) ? 'client-api-integration-documentation' : 'unverified';
        const hash = sha(value);
        const id = `${enclosingModule(p)}:${hash}`;
        if (collections.promptKeys.has(id) && actual) { const prior = collections.prompts.find(item => item.textSha256 === hash && item.module === enclosingModule(p)); if (prior) { prior.kind = 'actual-static-text'; prior.key = key; prior.purpose = purpose; } }
        if (!collections.promptKeys.has(id)) { collections.promptKeys.add(id); collections.prompts.push({ kind: actual ? 'actual-static-text' : 'candidate', purpose, serverPromptRecovered: false, key, text: value, textSha256: hash, source: provenance(p, origin), module: enclosingModule(p) }); }
      }
      return;
    }
    if (typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) value.forEach(item => inspectStrings(item, p, key, seen));
    else Object.entries(value).forEach(([k, item]) => inspectStrings(item, p, k, seen));
  }
  function request(p) {
    const node = p.node, callee = sourceCode(node.callee);
    if (!/(?:^|\.)(?:request|fetch|authenticatedRequest|connectSocket|WebSocket|EventSource)$/.test(callee) && !/Request$/.test(callee)) return;
    const first = evaluator.evaluate(node.arguments[0], p.scope);
    let object = first;
    const url = object && typeof object === 'object' && !Array.isArray(object) && !isUnknown(object) ? object.url ?? object.path : first;
    if (typeof url !== 'string' && !isUnknown(url)) return;
    const requestObject = object && typeof object === 'object' && !isUnknown(object) && !Array.isArray(object) ? object : {};
    const headers = requestObject.header ?? requestObject.headers;
    const data = requestObject.data ?? requestObject.body;
    collections.endpoints.push({ evidence: 'client-request-call', callee, module: enclosingModule(p), url: serial(url), base: serial(requestObject.apiBase ?? requestObject.baseUrl), method: serial(requestObject.method ?? (/fetch$/.test(callee) ? 'GET-default' : unresolved('default-method-not-inferred'))), headerNames: headers && typeof headers === 'object' && !isUnknown(headers) ? Object.keys(headers) : [], inputFieldNames: data && typeof data === 'object' && !isUnknown(data) ? Object.keys(data) : [], expression: sourceCode(node).slice(0, 6000), source: provenance(p, origin), serverImplementation: 'not-recovered' });
  }
  traverse(ast, {
    VariableDeclarator: { exit(p) { if (p.node.id.type !== 'Identifier') return; const binding = p.scope.getBinding(p.node.id.name); evaluator.set(binding, conditional(p) ? unresolved('conditional-initialization') : evaluator.evaluate(p.node.init, p.scope)); record(binding, p, 'initialization'); inspectStrings(evaluator.values.get(binding), p, p.node.id.name); } },
    AssignmentExpression: { exit(p) {
      if (p.node.left.type === 'Identifier') {
        const binding = p.scope.getBinding(p.node.left.name);
        const value = p.node.operator === '=' ? evaluator.evaluate(p.node.right, p.scope) : unresolved('compound-assignment');
        evaluator.set(binding, conditional(p) || binding?.scope.getFunctionParent() !== p.scope.getFunctionParent() ? unresolved('conditional-or-cross-function-assignment') : value);
        record(binding, p, 'assignment'); inspectStrings(value, p, p.node.left.name);
      }
      if (p.node.left.type === 'MemberExpression' && p.node.left.object.type === 'Identifier' && p.node.left.object.name !== '__COMMON_STYLESHEETS__') {
        const binding = p.scope.getBinding(p.node.left.object.name);
        if (binding && evaluator.values.has(binding)) {
          const receiver = evaluator.values.get(binding);
          if (receiver && typeof receiver === 'object' && !isUnknown(receiver)) {
            const key = p.node.left.computed ? evaluator.evaluate(p.node.left.property, p.scope) : keyOf(p.node.left.property);
            if (isUnknown(key) || forbidden(key) || conditional(p) || binding.scope.getFunctionParent() !== p.scope.getFunctionParent()) evaluator.set(binding, unresolved('dynamic-or-conditional-member-mutation', sourceCode(p.node)));
            else { const copy = Array.isArray(receiver) ? [...receiver] : Object.assign(Object.create(null), receiver); copy[key] = evaluator.evaluate(p.node.right, p.scope); evaluator.set(binding, copy); }
            record(binding, p, 'member-mutation');
          }
        }
      }
      if (p.node.left.type === 'MemberExpression' && p.node.left.object.type === 'Identifier' && p.node.left.object.name === '__COMMON_STYLESHEETS__') {
        const name = p.node.left.computed ? evaluator.evaluate(p.node.left.property, p.scope) : keyOf(p.node.left.property);
        const tokens = evaluator.evaluate(p.node.right, p.scope);
        if (typeof name === 'string' && Array.isArray(tokens)) collections.styleBlocks.push({ name, kind: 'common', tokens: serial(tokens), source: provenance(p, origin), hash: sha(JSON.stringify(serial(tokens))) });
      }
    } },
    CallExpression: { exit(p) {
      const node = p.node;
      const behavior = behaviorCall(p, origin);
      if (behavior) collections.behaviors.push(behavior);
      const mutated = evaluator.mutate(p); if (mutated) record(mutated, p, 'array-mutation');
      if (node.callee.type === 'Identifier' && node.callee.name === 'define' && node.arguments[0]?.type === 'StringLiteral') {
        const name = node.arguments[0].value, code = generate(node, { comments: false }).code + ';\n';
        const hash = sha(code), id = `${name}:${hash}`;
        const existing = collections.moduleMap.get(id);
        const originLoc = provenance(p, origin);
        if (existing) existing.sources.push(originLoc);
        else collections.moduleMap.set(id, { name, sha256: hash, classification: /(?:^|\/)@babel\/|(?:^|\/)runtime\//.test(name) ? 'runtime-helper' : 'business-or-library-module-unverified', sources: [originLoc], code });
      }
      if (node.callee.type === 'Identifier' && node.callee.name === 'setCssToHead') {
        const tokens = evaluator.evaluate(node.arguments[0], p.scope);
        let name = 'global';
        if (p.parentPath.isAssignmentExpression() && p.parentPath.node.left.type === 'MemberExpression') name = p.parentPath.node.left.property.value ?? p.parentPath.node.left.property.name ?? 'global';
        if (Array.isArray(tokens)) collections.styleBlocks.push({ name, kind: name === 'global' ? 'global' : 'page', tokens: serial(tokens), source: provenance(p, origin), hash: sha(JSON.stringify(serial(tokens))) });
        else collections.warnings.push({ code: 'unresolved-style-expression', source: provenance(p, origin), expression: sourceCode(node.arguments[0]).slice(0, 1000) });
      }
      request(p);
      if (node.callee.type === 'Identifier' && ['setInterval', 'setTimeout'].includes(node.callee.name)) collections.timers.push({ kind: node.callee.name, intervalMilliseconds: serial(evaluator.evaluate(node.arguments[1], p.scope)), callbackExpression: node.arguments[0] ? sourceCode(node.arguments[0]).slice(0, 6000) : null, source: provenance(p, origin), module: enclosingModule(p), meaning: 'client timer; runtime execution, HTTP refresh and server schedules are not inferred' });
      if (['Page', 'App', 'Component'].includes(keyOf(node.callee))) { const value = evaluator.evaluate(node.arguments[0], p.scope); inspectStrings(value, p); }
    } },
    StringLiteral(p) { if (/prompt|提示词|系统提示/i.test(p.node.value)) inspectStrings(p.node.value, p); }
  });
  for (const item of recordBindings.values()) {
    collections.configExpressions.push(item);
    if (typeof item.value === 'string' && /^https?:\/\//.test(item.value)) collections.endpoints.push({ evidence: 'static-url-binding', url: item.value, name: item.name, module: item.module, source: item.source, serverImplementation: 'not-recovered' });
    const values = Array.isArray(item.value) ? item.value : [item.value];
    for (const candidate of values) if (candidate && typeof candidate === 'object' && typeof candidate.path === 'string' && typeof candidate.method === 'string') collections.endpoints.push({ evidence: 'static-contract-object', path: candidate.path, method: candidate.method, parameterNames: Array.isArray(candidate.params) ? candidate.params.map(x => x?.name).filter(Boolean) : [], returnDocumentation: candidate.returns ?? null, source: item.source, module: item.module, serverImplementation: 'not-recovered' });
  }
}
function styleOutputs(blocks, warnings) {
  const unique = new Map();
  for (const b of blocks) { const key = `${b.name}:${b.hash}`; if (!unique.has(key)) unique.set(key, { ...b, sources: [b.source] }); else unique.get(key).sources.push(b.source); }
  const byName = new Map();
  for (const b of unique.values()) { const normalized = b.name.replace(/^\.\//, ''); const list = byName.get(normalized) ?? []; if (!list.some(item => item.hash === b.hash)) list.push(b); byName.set(normalized, list); }
  const warnKeys = new Set();
  function warning(code, b, details) { const key = JSON.stringify([code, b.name, details]); if (!warnKeys.has(key)) { warnKeys.add(key); warnings.push({ code, style: b.name, source: b.source, ...details }); } }
  function render(b, mode, seen = new Set()) {
    if (seen.has(b.hash)) { warning('cyclic-style-import', b, {}); return '/* unresolved cyclic import */'; }
    const next = new Set(seen).add(b.hash);
    return b.tokens.map(token => {
      if (typeof token === 'string') return token;
      if (!Array.isArray(token)) { warning('unknown-style-token', b, { token }); return '/* unresolved token */'; }
      if (token[0] === 0 && typeof token[1] === 'number') return mode === 'raw' ? `${token[1]}rpx` : `calc(var(--rpx) * ${token[1]})`;
      if (token[0] === 1) { warning('platform-style-token', b, { token, adaptation: 'preserved as comment; selector scope requires review' }); return `/* platform style token ${JSON.stringify(token)} */`; }
      if (token[0] === 2 && typeof token[1] === 'string') {
        if (mode === 'raw') return `@import ${JSON.stringify(token[1])};`;
        const imported = byName.get(token[1].replace(/^\.\//, ''));
        if (!imported) { warning('missing-style-import', b, { import: token[1] }); return '/* missing import ' + token[1].replace(/\*\//g, '') + ' */'; }
        if (imported.length > 1) { warning('conflicting-style-import', b, { import: token[1], hashes: imported.map(x => x.hash) }); return '/* conflicting import; review required */'; }
        return render(imported[0], mode, next);
      }
      warning('unknown-style-token', b, { token }); return '/* unresolved token */';
    }).join('');
  }
  return [...unique.values()].map(b => {
    const rawCss = render(b, 'raw');
    const browserCss = render(b, 'browser').replace(/\bwx-(button|image|view|text|textarea)\b/g, (_, name) => ({ button: 'button', image: 'img', view: 'div', text: 'span', textarea: 'textarea' }[name])).replace(/(-?\d+(?:\.\d+)?)rpx\b/g, 'calc(var(--rpx) * $1)');
    return { ...b, rawCss, browserCss, adaptation: 'partial; set --rpx from CSS viewport width / 750; generated WXML is not decompiled' };
  });
}
function analyzeEvidence(evidence, version, output) {
  evidence = path.resolve(evidence); output = path.resolve(output ?? path.join(evidence, 'analysis', String(version)));
  assertNoSymlinks(evidence); assertNoSymlinks(output);
  const manifestPath = confined(evidence, 'package-manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (![1, 2].includes(manifest.schema) || !Array.isArray(manifest.packages)) throw Error('Expected normalized manifest schema 1 or 2');
  if (!/^[A-Za-z0-9._-]+$/.test(String(version))) throw Error('Invalid version selector');
  const packages = manifest.packages.filter(p => String(p.version_directory) === String(version));
  if (!packages.length) throw Error('No packages match explicit version');
  const collections = { moduleMap: new Map(), styleBlocks: [], configExpressions: [], endpoints: [], prompts: [], promptKeys: new Set(), timers: [], behaviors: [], warnings: [] };
  if (manifest.schema === 1) collections.warnings.push({ code: 'legacy-normalized-schema', message: 'schema 1 accepted; migrate to schema 2 for current full validation' });
  let verifiedFiles = 0, parsedFiles = 0, inputBytes = 0;
  const cached = new Map();
  for (const pkg of packages) {
    if (pkg.status !== 'verified') { collections.warnings.push({ code: 'unverified-package-skipped', name: pkg.name, status: pkg.status }); continue; }
    if (!Array.isArray(pkg.files)) throw Error('Missing package files');
    const base = confined(evidence, pkg.extracted_directory);
    for (const entry of pkg.files) {
      if (++verifiedFiles > LIMITS.files) throw Error('File-count limit exceeded');
      const relative = safeRelative(entry.relative_path ?? String(entry.path || '').replace(/^\//, ''));
      if (entry.path !== undefined && entry.path !== '/' + relative) throw Error('Manifest archive path/relative_path mismatch');
      const file = confined(base, relative);
      const stat = fs.statSync(file); if (!stat.isFile() || stat.size > LIMITS.fileBytes) throw Error('Invalid/oversized evidence file');
      if (!/^[a-f0-9]{64}$/.test(entry.sha256 || '')) throw Error('Missing/invalid entry SHA256');
      const bytes = fs.readFileSync(file); if (sha(bytes) !== entry.sha256) throw Error('Evidence SHA256 mismatch: ' + relative);
      inputBytes += bytes.length;
      if (!/\.(?:js|cjs|mjs)$/.test(relative)) continue;
      const origin = { package: pkg.name, packageId: pkg.source_sha256 ?? null, version: String(version), relativePath: relative, fileSha256: entry.sha256 };
      if (cached.has(entry.sha256)) {
        const prior = cached.get(entry.sha256);
        // Identical compiled files preserve all module/style origins without reparsing.
        for (const [id, loc] of prior.modules) collections.moduleMap.get(id).sources.push({ ...loc, ...origin });
        for (const block of prior.styles) collections.styleBlocks.push({ ...block, source: { ...block.source, ...origin } });
        continue;
      }
      const startStyles = collections.styleBlocks.length, beforeModules = new Map([...collections.moduleMap].map(([id, m]) => [id, m.sources.length]));
      analyzeFile(bytes.toString('utf8'), origin, collections); parsedFiles++;
      const newModules = [];
      for (const [id, module] of collections.moduleMap) { const before = beforeModules.get(id) ?? 0; module.sources.slice(before).forEach(loc => newModules.push([id, loc])); }
      cached.set(entry.sha256, { modules: newModules, styles: collections.styleBlocks.slice(startStyles) });
      if ([collections.configExpressions, collections.endpoints, collections.prompts, collections.timers, collections.behaviors].some(items => items.length > LIMITS.records)) throw Error('Analysis record limit exceeded');
    }
  }
  const styles = styleOutputs(collections.styleBlocks, collections.warnings), modules = [...collections.moduleMap.values()];
  const conflicts = [];
  const namespace = new Map();
  for (const m of modules) { const hashes = namespace.get(m.name) ?? []; hashes.push(m.sha256); namespace.set(m.name, hashes); }
  for (const [name, hashes] of namespace) if (hashes.length > 1) conflicts.push({ name, hashes });
  fs.mkdirSync(output, { recursive: true });
  assertNoSymlinks(output);
  const artifact = (folder, stem, extension, content) => {
    const relative = `${folder}/${stem}.${extension}`, filename = confined(output, relative, false);
    fs.mkdirSync(path.dirname(filename), { recursive: true }); assertNoSymlinks(path.dirname(filename));
    if (lstatIfPresent(filename) && !lstatIfPresent(filename).isFile()) throw Error('Output is not a regular file');
    fs.writeFileSync(filename, content); return relative;
  };
  const moduleRecords = modules.map(m => { const { code, ...record } = m; return { ...record, extractedFile: artifact('modules', m.sha256, 'js', code) }; });
  const styleRecords = styles.map(s => { const { rawCss, browserCss, ...record } = s; return { ...record, rawFile: artifact('styles/raw', s.hash, 'css', rawCss), browserFile: artifact('styles/browser', s.hash, 'css', browserCss), tokensFile: artifact('styles/tokens', s.hash, 'json', JSON.stringify(s.tokens, null, 2)) }; });
  const result = { schema: 1, analyzerVersion: VERSION, sourceManifestSha256: sha(fs.readFileSync(manifestPath)), appid: manifest.appid ?? null, version: String(version), modules: moduleRecords, moduleConflicts: conflicts, styles: styleRecords, configExpressions: collections.configExpressions, endpoints: collections.endpoints, prompts: collections.prompts, timers: collections.timers, behaviors: collections.behaviors, warnings: collections.warnings, coverage: { selectedPackages: packages.length, verifiedPackages: packages.filter(p => p.status === 'verified').length, filesHashVerified: verifiedFiles, uniqueJavaScriptFilesParsed: parsedFiles, inputBytes, moduleNamespaces: namespace.size, moduleVariants: modules.length, runtimeModules: modules.filter(m => m.classification === 'runtime-helper').length, limits: LIMITS, limitation: 'Static client analysis only; no target code execution, full WXML decompile, dynamic server behavior or backend recovery.' } };
  const target = confined(output, 'analysis.json', false); fs.writeFileSync(target, JSON.stringify(result, null, 2) + '\n'); return result;
}
function main(args) {
  if (args.includes('--help')) { console.log('Usage: node scripts/analyze.cjs --out <verified-evidence> --version <explicit-version> [--analysis-out <separate-directory>]'); return; }
  const values = {};
  for (let i = 0; i < args.length; i += 2) { if (!['--out', '--version', '--analysis-out'].includes(args[i]) || !args[i + 1]) throw Error('Unknown or incomplete CLI option'); values[args[i]] = args[i + 1]; }
  if (!values['--out'] || !values['--version']) throw Error('--out and --version are required');
  const result = analyzeEvidence(values['--out'], values['--version'], values['--analysis-out']);
  console.log(JSON.stringify({ appid: result.appid, version: result.version, coverage: result.coverage, styles: result.styles.length, prompts: result.prompts.length, endpoints: result.endpoints.length, conflicts: result.moduleConflicts.length, warnings: result.warnings.length }));
}
module.exports = { analyzeEvidence, safeRelative, StaticEvaluator, analyzeFile, VERSION };
if (require.main === module) { try { main(process.argv.slice(2)); } catch (error) { console.error(JSON.stringify({ status: 'error', message: error.message })); process.exitCode = 1; } }
