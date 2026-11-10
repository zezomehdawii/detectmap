const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');
const source = fs.readFileSync(path.join(__dirname, '../lib/cmf-utils.ts'), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText;
const exportsObject = {};
new Function('exports', compiled)(exportsObject);
const { splitAttackDataSource, formatAttackDataSource, validRetention, apiErrorMessage } = exportsObject;

test('component selections split on the first colon and bare selections clear obsolete components', () => {
  assert.deepEqual(splitAttackDataSource(' Network Traffic: Network Traffic Content '), {
    attack_data_source: 'Network Traffic', attack_data_component: 'Network Traffic Content',
  });
  assert.deepEqual(splitAttackDataSource('Process'), { attack_data_source: 'Process', attack_data_component: null });
  assert.deepEqual(splitAttackDataSource(''), { attack_data_source: null, attack_data_component: null });
  assert.deepEqual(splitAttackDataSource('Source: Component: detail'), {
    attack_data_source: 'Source', attack_data_component: 'Component: detail',
  });
});

test('old combined mappings render once and canonical mappings round trip', () => {
  assert.equal(formatAttackDataSource('Network Traffic', 'Network Traffic Content'), 'Network Traffic: Network Traffic Content');
  assert.equal(formatAttackDataSource('Network Traffic: Network Traffic Content', 'Network Traffic Content'), 'Network Traffic: Network Traffic Content');
  assert.equal(formatAttackDataSource(null, 'stale component'), '');
});

test('retention accepts zero and clearing but rejects negative, fractional and invalid values', () => {
  for (const value of [null, undefined, 0, 60]) assert.equal(validRetention(value), true);
  for (const value of [-1, 1.5, NaN, Infinity]) assert.equal(validRetention(value), false);
});

test('FastAPI validation details become readable text without object children', () => {
  assert.equal(apiErrorMessage({ response: { data: { detail: [
    { loc: ['body', 'retention_days'], msg: 'Input should be greater than or equal to 0' },
  ] } } }), 'retention_days: Input should be greater than or equal to 0');
  assert.equal(apiErrorMessage({ response: { data: { detail: 'Source belongs to another asset' } } }), 'Source belongs to another asset');
  assert.equal(apiErrorMessage({ response: { data: { detail: { message: 'Validation failed' } } } }), 'Validation failed');
  assert.equal(apiErrorMessage({ response: { data: { detail: [{ unknown: true }] } } }, 'Save failed.'), 'Save failed.');
});
