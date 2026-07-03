import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import fs from 'node:fs'

import { evaluatePassword, POLICY } from './evaluator.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PORT = process.env.PORT || 4000
const app = express()

// Trust the first proxy hop so express-rate-limit sees the real client IP when
// deployed behind a load balancer / ingress (common in regulated cloud setups).
app.set('trust proxy', 1)

// --- Security posture --------------------------------------------------------
// Sensible secure defaults out of the box: no framework banner, HSTS, no-sniff,
// referrer policy, etc. This service handles secrets, so defence in depth first.
app.disable('x-powered-by')
app.use(helmet())
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') ?? true,
    methods: ['POST', 'GET'],
  }),
)

// Reject oversized bodies early (defends against memory-exhaustion DoS). A
// password of 128 chars is tiny, so 10kb is generous.
app.use(express.json({ limit: '10kb' }))

// Throttle abuse. The endpoint is unauthenticated by design (it is a strength
// oracle), so we cap per-IP request volume.
const limiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', message: 'Too many requests, slow down.' },
})

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'password-strength', uptime: process.uptime() })
})

app.get('/api/v1/password/policy', (_req, res) => {
  res.json(POLICY)
})

app.post('/api/v1/password/evaluate', limiter, (req, res) => {
  const { password, username, email } = req.body ?? {}

  if (typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({
      error: 'invalid_request',
      message: 'Field "password" is required and must be a non-empty string.',
    })
  }

  if (password.length > 4096) {
    // Guard against absurd inputs before handing them to the estimator.
    return res.status(413).json({
      error: 'password_too_long',
      message: 'Password exceeds the maximum accepted length.',
    })
  }

  try {
    const assessment = evaluatePassword({ password, username, email })
    // NOTE: the raw password is intentionally never echoed or logged.
    return res.status(200).json(assessment)
  } catch (err) {
    return res.status(400).json({ error: 'evaluation_failed', message: err.message })
  }
})

// --- Optional: serve the built SPA so the whole thing is one deployable ------
const distDir = path.resolve(__dirname, '..', 'dist')
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir))
  // SPA fallback: serve index.html for any non-API GET route. Express 5 uses
  // path-to-regexp v8, so we match with a RegExp instead of the legacy '*'.
  app.get(/^(?!\/api\/).*/, (_req, res) =>
    res.sendFile(path.join(distDir, 'index.html')),
  )
}

app.use((_req, res) => res.status(404).json({ error: 'not_found' }))

// Only bind a port when run directly (e.g. `node server/index.js`), so the app
// can be imported by tests without starting a listener.
const isMain = process.argv[1] === fileURLToPath(import.meta.url)
if (isMain) {
  app.listen(PORT, () => {
    console.log(`[password-strength] microservice listening on http://localhost:${PORT}`)
  })
}

export { app }
