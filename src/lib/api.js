const ENDPOINT = '/api/v1/password/evaluate'

/**
 * Call the password-strength microservice.
 * Returns the parsed assessment or throws with a friendly message.
 */
export async function evaluatePassword({ username, email, password }, signal) {
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password }),
    signal,
  })

  const data = await res.json().catch(() => null)

  if (!res.ok) {
    throw new Error(data?.message || `Request failed (${res.status})`)
  }
  return data
}
