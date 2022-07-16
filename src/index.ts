import { IncomingMessage, RequestListener, ServerResponse } from "http"
import vary from "vary"

/**
 * origin: Configures the Access-Control-Allow-Origin CORS header. Possible values:
 *  Boolean - set origin to true to reflect the request origin, as defined by req.header('Origin'), or set it to false to disable CORS.
 *  String - set origin to a specific origin. For example if you set it to "http://example.com" only requests from "http://example.com" will be allowed.
 *  RegExp - set origin to a regular expression pattern which will be used to test the request origin. If it's a match, the request origin will be reflected. For example the pattern /example\.com$/ will reflect any request that is coming from an origin ending with "example.com".
 *  Array - set origin to an array of valid origins. Each origin can be a String or a RegExp. For example ["http://example1.com", /\.example2\.com$/] will accept any request from "http://example1.com" or from a subdomain of "example2.com".
 *  Function - set origin to a function implementing some custom logic. The function takes the request origin as the first parameter and a callback (which expects the signature err [object], allow [bool]) as the second.
 * methods: Configures the Access-Control-Allow-Methods CORS header. Expects a comma-delimited string (ex: 'GET,PUT,POST') or an array (ex: ['GET', 'PUT', 'POST']).
 * allowedHeaders: Configures the Access-Control-Allow-Headers CORS header. Expects a comma-delimited string (ex: 'Content-Type,Authorization') or an array (ex: ['Content-Type', 'Authorization']). If not specified, defaults to reflecting the headers specified in the request's Access-Control-Request-Headers header.
 * exposedHeaders: Configures the Access-Control-Expose-Headers CORS header. Expects a comma-delimited string (ex: 'Content-Range,X-Content-Range') or an array (ex: ['Content-Range', 'X-Content-Range']). If not specified, no custom headers are exposed.
 * credentials: Configures the Access-Control-Allow-Credentials CORS header. Set to true to pass the header, otherwise it is omitted.
 * maxAge: Configures the Access-Control-Max-Age CORS header. Set to an integer to pass the header, otherwise it is omitted.
 * preflightContinue: Pass the CORS preflight response to the next handler.
 * optionsSuccessStatus: Provides a status code to use for successful OPTIONS requests, since some legacy browsers (IE11, various SmartTVs) choke on 204.
 *
 * "callback hell" is a feature of Express, embrace it here
 * (TODO: rearchitect the options & origin thunks)
 */

type Origin = boolean | string | RegExp | (string | RegExp)[]

type OriginCallback = (
  origin: IncomingMessage["headers"]["origin"],
  next: (err: any, origin: Origin) => void
) => void
function isOriginCallback(
  origin: Origin | OriginCallback
): origin is OriginCallback {
  return origin instanceof Function
}

interface Options {
  origin?: Origin
  methods?: string | string[]
  allowedHeaders?: string | string[]
  headers?: string | string[]
  exposedHeaders?: string | string[]
  credentials?: boolean
  maxAge?: number | string
  preflightContinue?: boolean
  optionsSuccessStatus?: number
}

type OptionsCallback = (
  req: IncomingMessage,
  next: (err: any, options: Options) => void
) => void

const defaults = {
  origin: "*",
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  preflightContinue: false,
  optionsSuccessStatus: 204,
} as Options

export default function expressMiddlewareFactory(
  corsOpts: Options | OptionsCallback
) {
  return function corsMiddleware(
    req: IncomingMessage,
    res: ServerResponse,
    next: (err?: any) => void
  ) {
    if (corsOpts instanceof Function) {
      corsOpts(req, corsMdlwrOptions)
    } else {
      corsMdlwrOptions(null, corsOpts)
    }

    function corsMdlwrOptions(err: any, options: Options) {
      if (err) {
        next(err)
        return
      }

      options = { ...defaults, ...options }
      if (options.origin) {
        if (isOriginCallback(options.origin)) {
          options.origin(req.headers.origin, corsMdlwrOrigin)
        } else {
          corsMdlwrOrigin(null, options.origin)
        }

        function corsMdlwrOrigin(err: any, origin: Origin) {
          if (err || !origin) {
            next(err)
            return
          }

          corsHandler({ ...options, origin }, req, res, next)
        }
      }

      next()
      return
    }
  }
}

// the functional handler, after options and options.origin are dynamically resolved
function corsHandler(
  options: {
    [k in keyof Options]: k extends "origin" ? Origin : Options[k]
  },
  req: IncomingMessage,
  res: ServerResponse,
  next: (err?: any) => void
) {
  if (
    req.method &&
    req.method.toUpperCase &&
    req.method.toUpperCase() === "OPTIONS"
  ) {
    // preflight request
    originHeaders()
    credentialsHeaders()
    methodsHeaders()
    allowedHeaders()
    cacheHeaders()
    exposedHeaders()

    if (options.preflightContinue) {
      next()
      return
    }

    res.statusCode = options.optionsSuccessStatus!
    res.setHeader("Content-Length", "0")
    res.end()
    return
  }

  // actual request
  originHeaders()
  credentialsHeaders()
  exposedHeaders()
  next()

  function originHeaders() {
    const { origin } = options
    const requestOrigin = req.headers.origin

    if (!origin || origin === "*") {
      // allow any origin
      res.setHeader("Access-Control-Allow-Origin", "*")
    } else if (isString(origin)) {
      // fixed origin
      vary(res, "Origin")
      res.setHeader("Access-Control-Allow-Origin", origin)
    } else {
      // reflect origin, or deny
      const allowedOrigin =
        isOriginAllowed(requestOrigin, origin) && requestOrigin
      if (allowedOrigin) {
        vary(res, "Origin")
        res.setHeader("Access-Control-Allow-Origin", allowedOrigin)
      }
    }

    function isString(s: Origin): s is string {
      return typeof s === "string" || s instanceof String
    }

    function isOriginAllowed(
      origin: IncomingMessage["headers"]["origin"],
      originAllowed: boolean | string | RegExp | (string | RegExp)[]
    ) {
      if (Array.isArray(originAllowed)) {
        return !!originAllowed.find((originAllowed) =>
          allowed(origin, originAllowed)
        )
      }

      return allowed(origin, originAllowed)

      function allowed(
        origin: IncomingMessage["headers"]["origin"],
        originAllowed: boolean | string | RegExp
      ) {
        if (originAllowed instanceof RegExp) {
          return originAllowed.test(origin!)
        }

        if (isString(originAllowed)) {
          return origin === originAllowed
        }

        return !!originAllowed
      }
    }
  }

  function credentialsHeaders() {
    const { credentials } = options
    if (credentials === true) {
      res.setHeader("Access-Control-Allow-Credentials", "true")
    }
  }

  function methodsHeaders() {
    let { methods } = options
    if (methods instanceof Array) {
      methods = methods.join(",") // stringify an array
    }

    if (methods) {
      res.setHeader("Access-Control-Allow-Methods", methods)
    }
  }

  function allowedHeaders() {
    let headers = options.allowedHeaders || options.headers
    if (headers) {
      if (headers instanceof Array) {
        headers = headers.join(",") // stringify an array
      }

      if (headers.length) {
        res.setHeader("Access-Control-Allow-Headers", headers)
      }
    } else if (req.headers["access-control-request-headers"]) {
      // .headers wasn't specified, so reflect the request headers
      vary(res, "Access-Control-Request-Headers")
      res.setHeader(
        "Access-Control-Allow-Headers",
        req.headers["access-control-request-headers"]
      )
    }
  }

  function cacheHeaders() {
    let { maxAge } = options
    maxAge = (typeof maxAge === "number" || maxAge) && maxAge.toString()
    if (maxAge && maxAge.length) {
      res.setHeader("Access-Control-Max-Age", maxAge)
    }
  }

  function exposedHeaders() {
    let { exposedHeaders } = options
    if (exposedHeaders) {
      if (exposedHeaders instanceof Array) {
        exposedHeaders = exposedHeaders.join(",") // stringify an array
      }

      if (exposedHeaders.length) {
        res.setHeader("Access-Control-Expose-Headers", exposedHeaders)
      }
    }
  }
}

export function asyncHandlerFactory(corsOpts: Options | OptionsCallback) {
  const corsMiddleware = expressMiddlewareFactory(corsOpts)
  return function corsHandler(req: IncomingMessage, res: ServerResponse) {
    return new Promise<void>((resolve, reject) => {
      corsMiddleware(req, res, (err: any) => {
        if (err) {
          reject(err)
          return
        }

        resolve()
      })
    })
  }
}
