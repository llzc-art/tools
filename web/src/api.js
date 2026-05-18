export async function apiGet(url) {
  const resp = await fetch(url)
  return resp.json()
}

export async function apiPost(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return resp.json()
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(String(text))
    return true
  } catch {
    return false
  }
}
