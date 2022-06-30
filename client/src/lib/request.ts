import {timeoutPromise, TimeoutError} from './utils'

const requestTimeout = 15000 // 15s

interface RequestOptions {
    method?: string
    headers?: Record<string, string>
    body?: BodyInit
    postData?: unknown
    timeout?: number
}

/**
 * Error returned by Request in case of a non-2xx status code
 */
export class ResponseNotOkError extends Error {
    statusCode?: number
}

/**
 * Response object
 */
export type Response<T> = {
    data: T
    ttl?: number
}

/**
 * Performs API requests.
 */
export async function Request<T>(url: string, options?: RequestOptions): Promise<Response<T>> {
    if (!options) {
        options = {}
    }

    // URL prefix
    if (URL_PREFIX) {
        url = URL_PREFIX + url
    }

    // Set the options
    const reqOptions: RequestInit = {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin',
    }
    const headers = new Headers()

    // HTTP method
    if (options.method) {
        reqOptions.method = options.method
    }

    // Headers
    if (options.headers && typeof options.headers == 'object') {
        for (const key in options.headers) {
            if (Object.prototype.hasOwnProperty.call(options.headers, key)) {
                headers.set(key, options.headers[key])
            }
        }
        reqOptions.headers = headers
    }

    // Request body
    // Disallow for GET and HEAD requests
    if (options.body && reqOptions.method != 'GET' && reqOptions.method != 'HEAD') {
        reqOptions.body = options.body
    }

    // POST data, if any
    if (options.postData) {
        // Ensure method is POST
        reqOptions.method = 'POST'
        reqOptions.body = JSON.stringify(options.postData)
        headers.set('Content-Type', 'application/json')
    }
    reqOptions.headers = headers

    // Timeout
    const controller = new AbortController()
    let timeout: number | null = null
    if (options.timeout === undefined || options.timeout === null || options.timeout > 0) {
        timeout = options.timeout || requestTimeout
        reqOptions.signal = controller.signal
    }

    // Make the request
    try {
        let p = fetch(url, reqOptions)
        if (timeout !== null) {
            p = timeoutPromise(p, timeout)
        }
        const response = await p

        // We're expecting a JSON document
        const ct = response.headers.get('content-type')
        if (!ct?.match(/application\/json/i)) {
            throw Error('Response was not JSON')
        }

        // Get the JSON data from the response
        const body = (await response.json()) as T

        // Check if we have a response with status code 200-299
        if (!response.ok) {
            const e = new ResponseNotOkError('Invalid response status code')
            e.statusCode = response.status
            if ((body as unknown as {error: string})?.error) {
                // eslint-disable-next-line no-console
                console.error('Invalid response status code')
                e.message = (body as unknown as {error: string}).error
            }
            throw e
        }

        // Get the TTL
        let ttl: number|undefined = undefined
        const ttlHeader = response.headers.get('x-session-ttl')
        if (ttlHeader) {
            ttl = parseInt(ttlHeader, 10)
            if (ttl < 1) {
                ttl = 0
            }
        }

        // Response
        return {
            data: body,
            ttl
        }
    }
    catch (err) {
        if (err instanceof TimeoutError) {
            controller.abort()
            throw Error('Request has timed out')
        }
        throw err
    }
}
