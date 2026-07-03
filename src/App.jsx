import { useEffect, useRef, useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  Eye,
  EyeOff,
  Check,
  X,
  AlertTriangle,
  Loader2,
  Lightbulb,
  Clock,
} from 'lucide-react'

import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { cn } from '@/lib/utils'
import { evaluatePassword } from '@/lib/api'
import { STRENGTH_META, CRACK_SCENARIOS } from '@/lib/strength'

function App() {
  const [form, setForm] = useState({
    username: 'okenobi',
    email: 'o.kenobi@jedi-council.com',
    password: '',
  })
  const [showPassword, setShowPassword] = useState(false)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const debounceRef = useRef(null)

  const update = (field) => (e) =>
    setForm((f) => ({ ...f, [field]: e.target.value }))

  // Live, debounced evaluation as the user types.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)

    if (!form.password) {
      setResult(null)
      setError(null)
      setLoading(false)
      return
    }

    const controller = new AbortController()
    setLoading(true)
    debounceRef.current = setTimeout(async () => {
      try {
        const data = await evaluatePassword(form, controller.signal)
        setResult(data)
        setError(null)
      } catch (err) {
        if (err.name !== 'AbortError') setError(err.message)
      } finally {
        setLoading(false)
      }
    }, 350)

    return () => {
      controller.abort()
      clearTimeout(debounceRef.current)
    }
  }, [form])

  const meta = result ? STRENGTH_META[result.score] : STRENGTH_META[0]

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-950 dark:to-slate-900">
      <div className="mx-auto max-w-5xl px-4 py-10 md:py-16">
        <header className="mb-8 flex flex-col items-center gap-3 text-center">
          <div className="flex size-12 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg">
            <ShieldCheck className="size-6" />
          </div>
          <h1 className="text-3xl font-semibold tracking-tight text-foreground">
            Password Strength Service
          </h1>
          <p className="max-w-xl text-sm text-muted-foreground">
            A microservice that scores passwords the way an attacker would — modelling
            guesses, not counting symbols. Aligned with NIST SP 800-63B.
          </p>
        </header>

        <div className="grid gap-6 md:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
          {/* --- Input card --- */}
          <Card className="h-fit">
            <CardHeader>
              <CardTitle>Credential check</CardTitle>
              <CardDescription>
                The username and email are sent as context so the service can flag
                passwords derived from personal info.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="flex flex-col gap-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  value={form.username}
                  onChange={update('username')}
                  autoComplete="off"
                  placeholder="okenobi"
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={form.email}
                  onChange={update('email')}
                  autoComplete="off"
                  placeholder="o.kenobi@jedi-council.com"
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={form.password}
                    onChange={update('password')}
                    autoComplete="new-password"
                    placeholder="Try 'Hello there!'"
                    className="pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((s) => !s)}
                    className="text-muted-foreground hover:text-foreground absolute inset-y-0 right-0 flex items-center pr-3"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? (
                      <EyeOff className="size-4" />
                    ) : (
                      <Eye className="size-4" />
                    )}
                  </button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Evaluated live as you type. The password is never stored or logged.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* --- Result card --- */}
          <Card className="h-fit">
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <CardTitle>Assessment</CardTitle>
                  <CardDescription>
                    Live result from the microservice.
                  </CardDescription>
                </div>
                {loading && (
                  <Loader2 className="size-4 animate-spin text-muted-foreground" />
                )}
              </div>
            </CardHeader>
            <CardContent className="flex flex-col gap-5">
              {!result && !error && (
                <EmptyState />
              )}

              {error && (
                <Alert variant="destructive">
                  <AlertTriangle />
                  <AlertTitle>Could not reach the service</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {result && !error && (
                <>
                  {/* Verdict */}
                  <div
                    className={cn(
                      'flex items-center justify-between rounded-lg p-3',
                      meta.ring,
                    )}
                  >
                    <div className="flex items-center gap-2">
                      {result.acceptable ? (
                        <ShieldCheck className={cn('size-5', meta.text)} />
                      ) : (
                        <ShieldAlert className={cn('size-5', meta.text)} />
                      )}
                      <span className={cn('font-semibold', meta.text)}>
                        {meta.label}
                      </span>
                    </div>
                    <Badge variant={result.acceptable ? 'default' : 'destructive'}>
                      {result.acceptable ? 'Meets policy' : 'Below policy'}
                    </Badge>
                  </div>

                  {/* Meter */}
                  <div className="flex flex-col gap-2">
                    <Progress
                      value={((result.score + 1) / 5) * 100}
                      indicatorClassName={meta.bar}
                    />
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>Strength {result.score}/4</span>
                      <span>~10^{result.guessesLog10} guesses to crack</span>
                    </div>
                  </div>

                  {/* Warning / suggestions */}
                  {(result.feedback.warning ||
                    result.feedback.suggestions.length > 0) && (
                    <Alert>
                      <Lightbulb />
                      <AlertTitle>
                        {result.feedback.warning || 'How to make it stronger'}
                      </AlertTitle>
                      {result.feedback.suggestions.length > 0 && (
                        <AlertDescription>
                          <ul className="list-disc pl-4">
                            {result.feedback.suggestions.map((s) => (
                              <li key={s}>{s}</li>
                            ))}
                          </ul>
                        </AlertDescription>
                      )}
                    </Alert>
                  )}

                  {/* Crack times */}
                  <div>
                    <h3 className="mb-2 flex items-center gap-1.5 text-sm font-medium">
                      <Clock className="size-4 text-muted-foreground" />
                      Estimated time to crack
                    </h3>
                    <div className="grid grid-cols-2 gap-2">
                      {CRACK_SCENARIOS.map((sc) => (
                        <div
                          key={sc.key}
                          className="rounded-lg border bg-card p-3"
                          title={sc.hint}
                        >
                          <div className="text-xs text-muted-foreground">
                            {sc.title}
                          </div>
                          <div className="text-sm font-semibold">
                            {result.crackTime[sc.key].display}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Policy checklist */}
                  <div>
                    <h3 className="mb-2 text-sm font-medium">Policy checks</h3>
                    <ul className="flex flex-col gap-1.5">
                      {result.policy.checks.map((check) => (
                        <li
                          key={check.id}
                          className="flex items-center gap-2 text-sm"
                        >
                          {check.passed ? (
                            <Check className="size-4 shrink-0 text-emerald-500" />
                          ) : (
                            <X
                              className={cn(
                                'size-4 shrink-0',
                                check.severity === 'required'
                                  ? 'text-red-500'
                                  : 'text-amber-500',
                              )}
                            />
                          )}
                          <span
                            className={cn(
                              !check.passed && 'text-muted-foreground',
                            )}
                          >
                            {check.label}
                          </span>
                          {check.severity === 'recommended' && (
                            <Badge variant="outline" className="ml-auto">
                              optional
                            </Badge>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>

        <footer className="mt-8 text-center text-xs text-muted-foreground">
          POST <code className="rounded bg-muted px-1 py-0.5">/api/v1/password/evaluate</code>{' '}
          · engine: zxcvbn-ts · standard: NIST SP 800-63B
        </footer>
      </div>
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-12 text-center">
      <ShieldCheck className="size-8 text-muted-foreground/50" />
      <p className="text-sm text-muted-foreground">
        Start typing a password to see its assessment.
      </p>
    </div>
  )
}

export default App
