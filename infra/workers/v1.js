import { connect } from 'cloudflare:sockets';

async function readStreamWithTimeout(stream, timeout) {
  let reader = stream.getReader();
  let buffer = '';
  let timeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Reading timed out')), timeout)
  );
  while (true) {
    try {
      const readPromise = reader.read();
      const { done, value} = await Promise.race([readPromise, timeoutPromise]);

      if (done) break;
      buffer += new TextDecoder().decode(value);
      return buffer;
    } catch (error) {
      if (buffer.length > 0) {
        return buffer;
      } else {
        throw error;
      }
    }
  }
  return buffer;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }
    if (request.headers.get('X-Api-Key') !== env['APIKEY']) {
      return new Response('Invalid API Key', { status: 401 });
    }

    let socket_timeout = parseInt(request.headers.get('X-Socket-Timeout')) || 2000;
    let targets = await request.json();
    let scan_results = [];
    for (const target of targets['targets']) {
      let scan_result = {"host": target['host'], "port": target['port'], "open": false, "data": ""}
      try {
        let s_options = { secureTransport: "off", allowHalfOpen: false}

        if (target['ssl']) {
          s_options = {secureTransport: "on", allowHalfOpen: false}
        }
        let socket = connect({'hostname': target['host'], 'port': target['port']}, s_options);
        if (target['data'].length > 0) {
          let writer = socket.writable.getWriter()
          let encoder = new TextEncoder();
          let encoded = encoder.encode(target['data'] + "\r\n");
          await writer.write(encoded);
        }
        scan_result['data'] = await readStreamWithTimeout(socket.readable, socket_timeout);
        scan_result['open'] = true;
      } catch (error) {
        scan_result['data'] = error
      }
      scan_results.push(scan_result)
    }
    return new Response(JSON.stringify({ scan_results }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
