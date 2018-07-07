###
PDFSecurity - represents PDF security settings
By Yang Liu
###

CryptoJS = require 'crypto-js'
saslprep = require 'saslprep'

class PDFSecurity
  @generateFileID: (info = {}) ->
    infoStr = "#{new Date().getTime()}\n"

    for own key, value of info
      infoStr += "#{key}: #{value.toString()}\n"

    return wordArrayToBuffer(CryptoJS.MD5(infoStr))

  @create: (document, options = {}) ->
    unless options.ownerPassword || options.userPassword
      return null

    return new PDFSecurity document, options

  constructor: (@document, options = {}) ->
    unless options.ownerPassword || options.userPassword
      throw new Error 'None of owner password and user password is defined.'

    @setupEncryption(options)

  setupEncryption: (options) ->
    @version = if options.aes256 then 5 else 4

    encDict =
      Filter: 'Standard'
      V: 0
      Length: 0
      CF:
        StdCF:
          AuthEvent: 'DocOpen'
      StmF: 'StdCF'
      StrF: 'StdCF'

    if @version == 5
      @setupEncryptionV5(encDict, options)
    else
      @setupEncryptionV4(encDict, options)

    @dictionary = @document.ref encDict

  setupEncryptionV4: (encDict, options) ->
    permissions = @getPermissions(options)

    paddedUserPassword = processPassword(4, options.userPassword)
    paddedOwnerPassword =
      if options.ownerPassword? and options.ownerPassword.length > 0
        processPassword(4, options.ownerPassword)
      else
        paddedUserPassword

    ownerPasswordEntry = @getOwnerPasswordV4(paddedUserPassword, paddedOwnerPassword, options)
    @encryptionKey = @getEncryptionKeyV4(paddedUserPassword, ownerPasswordEntry, permissions, options)
    userPasswordEntry = @getUserPasswordV4(@encryptionKey)

    encDict.V = 4
    encDict.Length = 128
    encDict.CF.StdCF.CFM = 'AESV2'
    encDict.CF.StdCF.Length = 16
    encDict.R = 4
    encDict.O = wordArrayToBuffer(ownerPasswordEntry)
    encDict.U = wordArrayToBuffer(userPasswordEntry)
    encDict.P = permissions

  setupEncryptionV5: (encDict, options) ->
    permissions = @getPermissions(options)

    processedUserPassword = processPassword(5, options.userPassword)
    processedOwnerPassword =
      if options.ownerPassword? and options.ownerPassword.length > 0
        processPassword(5, options.ownerPassword)
      else
        processedUserPassword

    @encryptionKey = @getEncryptionKeyV5()
    userPasswordEntry = @getUserPasswordV5(processedUserPassword)
    userKeySalt = CryptoJS.lib.WordArray.create([userPasswordEntry.words[10], userPasswordEntry.words[11]], 8)
    userEncryptionKeyEntry = @getUserEncryptionKeyV5(processedUserPassword, userKeySalt, @encryptionKey)
    ownerPasswordEntry = @getOwnerPasswordV5(processedOwnerPassword, userPasswordEntry)
    ownerKeySalt = CryptoJS.lib.WordArray.create([ownerPasswordEntry.words[10], ownerPasswordEntry.words[11]], 8)
    ownerEncryptionKeyEntry = @getOwnerEncryptionKeyV5(processedOwnerPassword, ownerKeySalt, userPasswordEntry,
      @encryptionKey)
    permsEntry = @getEncryptedPermissions(permissions, @encryptionKey)

    encDict.V = 5
    encDict.Length = 256
    encDict.CF.StdCF.CFM = 'AESV3'
    encDict.CF.StdCF.Length = 32
    encDict.R = 5
    encDict.O = wordArrayToBuffer(ownerPasswordEntry)
    encDict.OE = wordArrayToBuffer(ownerEncryptionKeyEntry)
    encDict.U = wordArrayToBuffer(userPasswordEntry)
    encDict.UE = wordArrayToBuffer(userEncryptionKeyEntry)
    encDict.P = permissions
    encDict.Perms = wordArrayToBuffer(permsEntry)

  getPermissions: (options) ->
    permissions = 0xfffff0c0 >> 0
    permissions |= 0b000000000100 if options.allowPrinting == 'lowResolution'
    permissions |= 0b100000000100 if options.allowPrinting == 'highResolution'
    permissions |= 0b000000001000 if options.allowModifying
    permissions |= 0b000000010000 if options.allowCopying
    permissions |= 0b000000100000 if options.allowAnnotating
    permissions |= 0b000100000000 if options.allowFillingForms
    permissions |= 0b001000000000 if options.allowContentAccessibility
    permissions |= 0b010000000000 if options.allowDocumentAssembly
    return permissions

  getUserPasswordV4: (encryptionKey) ->
    cipher = CryptoJS.MD5(processPassword(4).concat(CryptoJS.lib.WordArray.create(@document.id)))
    key = encryptionKey.clone()
    for i in [0..19]
      for j in [0..4]
        key.words[j] = encryptionKey.words[j] ^ (i | (i << 8) | (i << 16) | (i << 24))
      cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext
    return cipher.concat(CryptoJS.lib.WordArray.create(null, 16))

  getOwnerPasswordV4: (paddedUserPassword, paddedOwnerPassword) ->
    digest = CryptoJS.MD5(paddedOwnerPassword)
    for i in [0..49]
      digest = CryptoJS.MD5(digest)
    key = digest.clone()
    cipher = paddedUserPassword
    for i in [0..19]
      for j in [0..4]
        key.words[j] = digest.words[j] ^ (i | (i << 8) | (i << 16) | (i << 24))
      cipher = CryptoJS.RC4.encrypt(cipher, key).ciphertext
    return cipher

  getEncryptionKeyV4: (paddedUserPassword, ownerPasswordEntry, permissions) ->
    key = paddedUserPassword.clone()
      .concat(ownerPasswordEntry)
      .concat(CryptoJS.lib.WordArray.create([lsbFirstWord(permissions)], 4))
      .concat(CryptoJS.lib.WordArray.create(@document.id))
    for i in [0..50]
      key = CryptoJS.MD5(key)
    return key

  getUserPasswordV5: (processedUserPassword) ->
    validationSalt = CryptoJS.lib.WordArray.random(8)
    keySalt = CryptoJS.lib.WordArray.random(8)
    return CryptoJS.SHA256(processedUserPassword.clone().concat(validationSalt))
      .concat(validationSalt).concat(keySalt)

  getUserEncryptionKeyV5: (processedUserPassword, userKeySalt, encryptionKey) ->
    key = CryptoJS.SHA256(processedUserPassword.clone().concat(userKeySalt))
    options =
      mode: CryptoJS.mode.CBC
      padding: CryptoJS.pad.NoPadding
      iv: CryptoJS.lib.WordArray.create(null, 16)
    return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext

  getOwnerPasswordV5: (processedOwnerPassword, userPasswordEntry) ->
    validationSalt = CryptoJS.lib.WordArray.random(8)
    keySalt = CryptoJS.lib.WordArray.random(8)
    return CryptoJS.SHA256(processedOwnerPassword.clone().concat(validationSalt).concat(userPasswordEntry))
      .concat(validationSalt).concat(keySalt)

  getOwnerEncryptionKeyV5: (processedOwnerPassword, ownerKeySalt, userPasswordEntry, encryptionKey) ->
    key = CryptoJS.SHA256(processedOwnerPassword.clone().concat(ownerKeySalt).concat(userPasswordEntry))
    options =
      mode: CryptoJS.mode.CBC
      padding: CryptoJS.pad.NoPadding
      iv: CryptoJS.lib.WordArray.create(null, 16)
    return CryptoJS.AES.encrypt(encryptionKey, key, options).ciphertext

  getEncryptionKeyV5: () ->
    CryptoJS.lib.WordArray.random(32)

  getEncryptedPermissions: (permissions, encryptionKey) ->
    cipher = CryptoJS.lib.WordArray.create([lsbFirstWord(permissions), 0xffffffff, 0x54616462], 12)
      .concat(CryptoJS.lib.WordArray.random(4))
    options =
      mode: CryptoJS.mode.ECB
      padding: CryptoJS.pad.NoPadding
    return CryptoJS.AES.encrypt(cipher, encryptionKey, options).ciphertext

  getEncryptFn: (obj, gen) ->
    if @version == 4
      key = CryptoJS.MD5(@encryptionKey.clone().concat(CryptoJS.lib.WordArray.create([
        ((obj & 0xff) << 24) | ((obj & 0xff00) << 8) | ((obj >> 8) & 0xff00) | (gen & 0xff)
        (gen & 0xff00) << 16 | 0x0073416c
        0x54000000], 9)))
    else
      key = @encryptionKey
    iv = CryptoJS.lib.WordArray.random(16)

    return (buffer) ->
      options =
        mode: CryptoJS.mode.CBC
        padding: CryptoJS.pad.Pkcs7
        iv: iv
      return wordArrayToBuffer(
        iv.clone().concat(CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(buffer), key, options).ciphertext))

  end: ->
    @dictionary.end()

  processPassword = (version, password = '') ->
    if version == 5
      password = unescape(encodeURIComponent(saslprep(password)))
      length = Math.min(127, password.length)
      out = new Buffer(length)

      for index in [0..length - 1]
        out[index] = password.charCodeAt(index)

    else
      out = new Buffer(32)
      index = 0
      length = password.length

      while index < length and index < 32
        code = password.charCodeAt(index)
        if code > 0xff
          throw new Error 'Password contains one or more invalid characters.'
        out[index] = code
        index++

      while index < 32
        out[index] = PASSWORD_PADDING[index - length]
        index++

    return CryptoJS.lib.WordArray.create(out)

  lsbFirstWord = (data) ->
    ((data & 0xff) << 24) | ((data & 0xff00) << 8) | ((data >> 8) & 0xff00) | ((data >> 24) & 0xff)

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
