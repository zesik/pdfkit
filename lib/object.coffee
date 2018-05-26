###
PDFObject - converts JavaScript types into their corresponding PDF types.
By Devon Govett
###

class PDFObject
  pad = (str, length) ->
    (Array(length + 1).join('0') + str).slice(-length)

  escapableRe = /[\n\r\t\b\f\(\)\\]/g
  escapable =
    '\n': '\\n'
    '\r': '\\r'
    '\t': '\\t'
    '\b': '\\b'
    '\f': '\\f'
    '\\': '\\\\'
    '(': '\\('
    ')': '\\)'

  # Convert little endian UTF-16 to big endian
  swapBytes = (buff) ->
    l = buff.length
    if l & 0x01
      throw new Error("Buffer length must be even")
    else
      for i in [0...l - 1] by 2
        a = buff[i]
        buff[i] = buff[i + 1]
        buff[i+1] = a

    return buff

  @convert: (object, encryptFn = null) ->
    # String literals are converted to the PDF name type
    if typeof object is 'string'
      '/' + object

    # String objects are converted to PDF strings (UTF-16)
    else if object instanceof String
      string = object
      # Detect if this is a unicode string
      isUnicode = false
      for i in [0...string.length] by 1
        if string.charCodeAt(i) > 0x7f
          isUnicode = true
          break

      # If so, encode it as big endian UTF-16
      if isUnicode
        stringBuffer = swapBytes(new Buffer('\ufeff' + string, 'utf16le'))
      else
        stringBuffer = new Buffer(string, 'ascii')

      # Encrypt the string when necessary
      if encryptFn?
        string = encryptFn(stringBuffer).toString('binary')
      else
        string = stringBuffer.toString('binary')

      # Escape characters as required by the spec
      string = string.replace escapableRe, (c) ->
        return escapable[c]

      '(' + string + ')'

    # Buffers are converted to PDF hex strings
    else if Buffer.isBuffer(object)
      '<' + object.toString('hex') + '>'

    else if object instanceof PDFReference
      object.toString()

    else if object instanceof Date
      string = 'D:' + pad(object.getUTCFullYear(), 4) +
                      pad(object.getUTCMonth() + 1, 2) +
                      pad(object.getUTCDate(), 2) +
                      pad(object.getUTCHours(), 2) +
                      pad(object.getUTCMinutes(), 2) +
                      pad(object.getUTCSeconds(), 2) + 'Z'

      # Encrypt the string when necessary
      if encryptFn?
        string = encryptFn(new Buffer(string, 'ascii')).toString('binary')

        # Escape characters as required by the spec
        string = string.replace escapableRe, (c) ->
          return escapable[c]

      '(' + string + ')'

    else if Array.isArray object
      items = (PDFObject.convert(e, encryptFn) for e in object).join(' ')
      '[' + items + ']'

    else if {}.toString.call(object) is '[object Object]'
      out = ['<<']
      for key, val of object
        out.push '/' + key + ' ' + PDFObject.convert(val, encryptFn)

      out.push '>>'
      out.join '\n'

    else if typeof object is 'number'
      PDFObject.number object

    else
      '' + object

  @number: (n) ->
    if n > -1e21 and n < 1e21
      return Math.round(n * 1e6) / 1e6

    throw new Error "unsupported number: #{n}"

module.exports = PDFObject
PDFReference = require './reference'
