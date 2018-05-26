###
PDFSecurity - represents PDF security settings
By Yang Liu
###

CryptoJS = require 'crypto-js'

class PDFSecurity
  @generateFileID: (info = {}) ->
    infoStr = "#{new Date().getTime()}\n"

    for own key, value of info
      infoStr += "#{key}: #{value.toString()}\n"

    return wordArrayToBuffer(CryptoJS.MD5(infoStr))

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

    ownerValueKey = CryptoJS.MD5(paddedOwnerPassword)
    ownerValueKey.sigBytes = 5
    ownerValue = CryptoJS.RC4.encrypt(paddedUserPassword, ownerValueKey).ciphertext

    userValueSrc =
      paddedUserPassword
        .concat(ownerValue)
        .concat(CryptoJS.lib.WordArray.create([0x00ffffff | ((permissions & 0xff) << 24)], 4))
        .concat(CryptoJS.lib.WordArray.create(@document.id))
    @encryptionKey = CryptoJS.MD5(userValueSrc)
    @encryptionKey.sigBytes = 5
    userValue = CryptoJS.RC4.encrypt(padPassword(), @encryptionKey).ciphertext

    @dictionary = @document.ref
      Filter: 'Standard'
      V: 1
      R: 2
      O: wordArrayToBuffer(ownerValue)
      U: wordArrayToBuffer(userValue)
      P: permissions

  getEncryptFn: (obj, gen) ->
    key = CryptoJS.MD5(@encryptionKey.clone().concat(CryptoJS.lib.WordArray.create(Buffer.from([
      obj & 0xff
      (obj >> 8) & 0xff
      (obj >> 16) & 0xff
      gen & 0xff
      (gen >> 8) & 0xff
    ]))))
    key.sigBytes = 10

    return (buffer) ->
      wordArrayToBuffer(CryptoJS.RC4.encrypt(CryptoJS.lib.WordArray.create(buffer), key).ciphertext)

  end: ->
    @dictionary.end()

  padPassword = (password = '') ->
    out = new Buffer(32)
    index = 0
    length = password.length

    while index < length and index < 32
      code = password.charCodeAt(index)
      if code > 0xff
        throw new Error 'Password contains one or more invalid character.'
      out[index] = code
      index++

    while index < 32
      out[index] = PASSWORD_PADDING[index - length]
      index++

    return CryptoJS.lib.WordArray.create(out)

  wordArrayToBuffer = (wordArray) ->
    byteArray = []
    for i in [0..wordArray.sigBytes - 1]
      byteArray.push((wordArray.words[Math.floor(i / 4)] >> (8 * (3 - i % 4))) & 0xff)
    return Buffer.from(byteArray)

  PASSWORD_PADDING = [
    0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08
    0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
  ]

module.exports = PDFSecurity
