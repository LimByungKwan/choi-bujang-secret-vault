import { createClient } from '@supabase/supabase-js';

function logSupabaseFailure(error, status) {
  const code = typeof error?.code === 'string' && /^[A-Za-z0-9_-]{1,32}$/u.test(error.code)
    ? error.code
    : 'UNKNOWN';
  const httpStatus = Number.isInteger(error?.status) ? error.status : status;
  console.error('Supabase notes query failed', {
    code,
    status: Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599 ? httpStatus : null,
  });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) {
    return response.status(503).json({ error: 'NOTES_SERVICE_NOT_CONFIGURED' });
  }

  try {
    const supabase = createClient(supabaseUrl, secretKey, {
      auth: { autoRefreshToken: false, detectSessionInUrl: false, persistSession: false },
    });
    const { data, error, status } = await supabase
      .from('learning_notes')
      .select('title,content')
      .order('created_at', { ascending: true });
    if (error) {
      logSupabaseFailure(error, status);
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    return response.status(200).json({ notes: data });
  } catch (error) {
    logSupabaseFailure(error);
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}