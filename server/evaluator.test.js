import { test } from 'node:test'
import assert from 'node:assert/strict'

import { evaluatePassword } from './evaluator.js'

test('rejects an empty password', () => {
  assert.throws(() => evaluatePassword({ password: '' }))
})

test('the example password returns a well-formed assessment', () => {
  const r = evaluatePassword({
    username: 'okenobi',
    email: 'o.kenobi@jedi-council.com',
    password: 'Hello there!',
  })
  assert.ok(r.score >= 0 && r.score <= 4)
  assert.ok(['very-weak', 'weak', 'fair', 'strong', 'very-strong'].includes(r.label))
  assert.equal(r.policy.checks.length, 6)
  assert.ok('offlineSlowHashing' in r.crackTime)
})

test('a common password is flagged', () => {
  const r = evaluatePassword({ password: 'Password123!' })
  assert.equal(r.acceptable, false)
  assert.ok(r.score <= 2)
})

test('password containing the username fails the personal-info check', () => {
  const r = evaluatePassword({
    username: 'okenobi',
    email: 'o.kenobi@jedi-council.com',
    password: 'okenobi-super-secret-1',
  })
  const personal = r.policy.checks.find((c) => c.id === 'no_personal_info')
  assert.equal(personal.passed, false)
})

test('a long random passphrase is accepted and strong', () => {
  const r = evaluatePassword({
    username: 'okenobi',
    email: 'o.kenobi@jedi-council.com',
    password: 'correct-horse-battery-staple-97!',
  })
  assert.equal(r.acceptable, true)
  assert.ok(r.score >= 3, `expected strong score, got ${r.score}`)
})

test('short but complex passwords still fail the minimum length gate', () => {
  const r = evaluatePassword({ password: 'aB3$xY' })
  const minLen = r.policy.checks.find((c) => c.id === 'min_length')
  assert.equal(minLen.passed, false)
  assert.equal(r.acceptable, false)
})

test('response never contains the raw password', () => {
  const r = evaluatePassword({ password: 'correct-horse-battery-staple-97!' })
  assert.ok(!JSON.stringify(r).includes('correct-horse'))
})
