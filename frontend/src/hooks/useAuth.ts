import { useEffect, useState } from 'react'
import type { User, Session } from '@supabase/supabase-js'
import { supabase } from '@/lib/supabase'

export function useAuth() {
  const [user, setUser] = useState<User | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [username, setUsername] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  async function fetchUsername(userId: string) {
    const { data } = await supabase
      .from('user_preferences')
      .select('username')
      .eq('user_id', userId)
      .single()
    setUsername(data?.username ?? null)
  }

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session)
      setUser(session?.user ?? null)
      if (session?.user) fetchUsername(session.user.id)
      setLoading(false)
    })

    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (_event, session) => {
        setSession(session)
        setUser(session?.user ?? null)
        if (session?.user) {
          fetchUsername(session.user.id)
        } else {
          setUsername(null)
        }
        setLoading(false)
      },
    )

    return () => subscription.unsubscribe()
  }, [])

  async function login(email: string, password: string) {
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    if (error) throw error
  }

  async function register(email: string, password: string, name: string) {
    const { data, error } = await supabase.auth.signUp({ email, password })
    if (error) throw error
    if (data.user) {
      await supabase.from('user_preferences').upsert({
        user_id: data.user.id,
        username: name,
        updated_at: new Date().toISOString(),
      })
      setUsername(name)
    }
  }

  async function logout() {
    const { error } = await supabase.auth.signOut()
    if (error) throw error
  }

  return { user, session, username, loading, login, logout, register }
}
