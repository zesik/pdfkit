###
PDFSecurity - represents PDF security settings
By Yang Liu
###

hex = require 'crypto-js/enc-hex'
md5 = require 'crypto-js/md5'
rc4 = require 'crypto-js/rc4'

class PDFSecurity
  @generateFileID: (info = {}) ->
    infoStr = "#{new Date().getTime()}\n"

    for own key, value of info
      infoStr += "#{key}: #{value.toString()}\n"

    return new Buffer(md5(infoStr).toString(), 'hex')

  @create: (document, options = {}) ->
    unless options.ownerPassword? || options.userPassword?
      return null

    return new PDFSecurity document, options

  constructor: (@document, options = {}) ->
    unless options.ownerPassword? || options.userPassword?
      throw new Error 'None of owner password and user password is defined.'

    permissions = ~0b111111
    permissions |= 0b000100 if options.allowPrinting
    permissions |= 0b001000 if options.allowModifying
    permissions |= 0b010000 if options.allowCopying
    permissions |= 0b100000 if options.allowAnnotating

    paddedUserPassword = padPassword(options.userPassword)
    paddedOwnerPassword =
      if options.ownerPassword? and options.ownerPassword.length > 0
        padPassword(options.ownerPassword)
      else
        paddedUserPassword

    ownerValueKey = md5(hex.parse(paddedOwnerPassword)).toString(hex)[0..9]
    ownerValue = rc4.encrypt(hex.parse(paddedUserPassword), hex.parse(ownerValueKey)).ciphertext.toString(hex)

    userValueSrc =
      paddedUserPassword +
      ownerValue +
      padHex(permissions & 0xff) + 'ffffff' +
      @document.id.toString('hex')
    @encryptionKey = md5(hex.parse(userValueSrc)).toString(hex)[0..9]
    userValue = rc4.encrypt(hex.parse(padPassword()), hex.parse(@encryptionKey)).ciphertext.toString(hex)

    @dictionary = @document.ref
      Filter: 'Standard'
      V: 1
      R: 2
      O: new Buffer(ownerValue, 'hex')
      U: new Buffer(userValue, 'hex')
      P: permissions

  getEncryptFn: (obj, gen) ->
    key = hex.parse(md5(hex.parse(
      @encryptionKey +
      padHex(obj & 0xff) +
      padHex((obj >> 8) & 0xff) +
      padHex((obj >> 16) & 0xff) +
      padHex(gen & 0xff) +
      padHex((gen >> 8) & 0xff)
    )).toString()[0..19])

    return (data) ->
      rc4.encrypt(hex.parse(data), key).ciphertext.toString(hex)

  end: ->
    @dictionary.end()

  padPassword = (password = '') ->
    out = ''
    index = 0
    length = password.length

    while index < length and index < 32
      code = password.charCodeAt(index++)
      if code > 0xff
        throw new Error 'Password contains one or more invalid character.'
      out += padHex(code)

    while index < 32
      out += padHex(PASSWORD_PADDING[index++ - length])

    return out

  padHex = (value) ->
    return ('00' + value.toString(16)).slice(-2)

  PASSWORD_PADDING = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
  ]

module.exports = PDFSecurity
