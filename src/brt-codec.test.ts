import * as api from './brt-codec'

function toHex(bytes: Buffer) {
  return Buffer.from(bytes).toString('hex').toUpperCase()
}

function toBytes(hex: string) {
  return Buffer.from(hex, 'hex')
}

/**
 * Create a test case for encoding data and a test case for decoding data.
 *
 * @param encoder Encoder function to test
 * @param decoder Decoder function to test
 * @param base58 Base58-encoded string to decode
 * @param hex Hexadecimal representation of expected decoded data
 */
function makeEncodeDecodeTest(encoder: Function, decoder: Function, base58: string, hex: string) {
  test(`can translate between ${hex} and ${base58}`, function() {
    const actual = encoder(toBytes(hex))
    expect(actual).toBe(base58)
  })
  test(`can translate between ${base58} and ${hex})`, function() {
    const buf = decoder(base58)
    expect(toHex(buf)).toBe(hex)
  })
}

makeEncodeDecodeTest(api.encodeAccountID, api.decodeAccountID, 'bHbQLCqQCbBgsUoMrCu6UWPcVy42Xf6NbD',
  'BA8E78626EE42C41B46D46C3048DF3A1C3C87072')

makeEncodeDecodeTest(api.encodeNodePublic, api.decodeNodePublic,
  'h3KFiHtRNLf1qzB7veSF9dHWBindiZiUEb77EZ5HKmcMHMN85i4v',
  '032ED4D80AC2383BDF25AFB282930CE26668D7FC0FCFE20CA620972009403662AB')

  makeEncodeDecodeTest(api.encodeAccountPublic, api.decodeAccountPublic,
    'nwPNiQY5TQXqCpGi8BDh5qxvAuVU6VkHPnqPwk3xmfuLECckomre',
    '032ED4D80AC2383BDF25AFB282930CE26668D7FC0FCFE20CA620972009403662AB')

test('can decode arbitrary seeds', function() {
  const decoded = api.decodeSeed('tNcSG5rcM3gmds5LFpUQaqQPjvhoDLH')
  expect(toHex(decoded.bytes)).toBe('47165A58B08D4E10D60533ACFCCFD2FB')
  expect(decoded.type).toBe('ed25519')

  const decoded2 = api.decodeSeed('ttYtgJoAzFm9qnZXctLs97qEcXhcR')
  expect(toHex(decoded2.bytes)).toBe('3D905024239E36212668429331837367')
  expect(decoded2.type).toBe('secp256k1')
})

test('can pass a type as second arg to encodeSeed', function() {

  const edSeed = 'tNcSG5rcM3gmds5LFpUQaqQPjvhoDLH'
  const decoded = api.decodeSeed(edSeed)
  const type = 'ed25519'
  expect(toHex(decoded.bytes)).toBe('47165A58B08D4E10D60533ACFCCFD2FB')
  expect(decoded.type).toBe(type)
  expect(api.encodeSeed(decoded.bytes, type)).toBe(edSeed)
})

test('isValidClassicAddress - secp256k1 address valid', function() {
  expect(api.isValidClassicAddress('bJwZDLvLrDSLV5XP89ADJW1Qq1mF87g44A')).toBe(true)
})

test('isValidClassicAddress - ed25519 address valid', function() {
  expect(api.isValidClassicAddress('btWZxuKqsfieVcxwvJXH8TbsQmWF2uAGNx')).toBe(true)
})

test('isValidClassicAddress - invalid', function() {
  expect(api.isValidClassicAddress('btWZxuKqsfieVcxwvJXH8TbsQmWF2uAGNt')).toBe(false)
})

test('isValidClassicAddress - empty', function() {
  expect(api.isValidClassicAddress('')).toBe(false)
})

describe('encodeSeed', function() {

  it('encodes a secp256k1 seed', function() {
    const result = api.encodeSeed(Buffer.from('3D905024239E36212668429331837367', 'hex'), 'secp256k1')
    expect(result).toBe('ttYtgJoAzFm9qnZXctLs97qEcXhcR')
  })

  it('encodes low secp256k1 seed', function() {
    const result = api.encodeSeed(Buffer.from('00000000000000000000000000000000', 'hex'), 'secp256k1')
    expect(result).toBe('trgHRTaiMwu9oXmL9g2S1KJVnu8Bt')
  })

  it('encodes high secp256k1 seed', function() {
    const result = api.encodeSeed(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'hex'), 'secp256k1')
    expect(result).toBe('tnE9wQQdFBDJuVDKrBAFmqmDjWN4D')
  })

  it('encodes an ed25519 seed', function() {
    const result = api.encodeSeed(Buffer.from('47165A58B08D4E10D60533ACFCCFD2FB', 'hex'), 'ed25519')
    expect(result).toBe('tNcSG5rcM3gmds5LFpUQaqQPjvhoDLH')
  })

  it('encodes low ed25519 seed', function() {
    const result = api.encodeSeed(Buffer.from('00000000000000000000000000000000', 'hex'), 'ed25519')
    expect(result).toBe('tNcRHGRM8qAczT9ZWZhqiCoqF12HGFN')
  })

  it('encodes high ed25519 seed', function() {
    const result = api.encodeSeed(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 'hex'), 'ed25519')
    expect(result).toBe('tNc7i3wKadPdJcNWyXAMDs54HdgWwaE')
  })

  test('attempting to encode a seed with less than 16 bytes of entropy throws', function() {
    expect(() => {
      api.encodeSeed(Buffer.from('CF2DE378FBDD7E2EE87D486DFB5A7B', 'hex'), 'secp256k1')
    }).toThrow('entropy must have length 16')
  })

  test('attempting to encode a seed with more than 16 bytes of entropy throws', function() {
    expect(() => {
      api.encodeSeed(Buffer.from('3D905024239E36212668429331837367FF', 'hex'), 'secp256k1')
    }).toThrow('entropy must have length 16')
  })
})

describe('decodeSeed', function() {

  it('can decode an Ed25519 seed', function() {
    const decoded = api.decodeSeed('tNcSG5rcM3gmds5LFpUQaqQPjvhoDLH')
    expect(toHex(decoded.bytes)).toBe('47165A58B08D4E10D60533ACFCCFD2FB')
    expect(decoded.type).toBe('ed25519')
  })

  it('can decode a secp256k1 seed', function() {
    const decoded = api.decodeSeed('ttYtgJoAzFm9qnZXctLs97qEcXhcR')
    expect(toHex(decoded.bytes)).toBe('3D905024239E36212668429331837367')
    expect(decoded.type).toBe('secp256k1')
  })
})

describe('encodeAccountID', function() {

  it('can encode an AccountID', function() {
    const encoded = api.encodeAccountID(Buffer.from('BA8E78626EE42C41B46D46C3048DF3A1C3C87072', 'hex'))
    expect(encoded).toBe('bHbQLCqQCbBgsUoMrCu6UWPcVy42Xf6NbD')
  })

  test('unexpected length should throw', function() {
    expect(() => {
      api.encodeAccountID(Buffer.from('ABCDEF', 'hex'))
    }).toThrow(
      'unexpected_payload_length: bytes.length does not match expectedLength'
    )
  })
})

describe('decodeNodePublic', function() {

  it('can decode a NodePublic', function() {
    const decoded = api.decodeNodePublic('h3KFiHtRNLf1qzB7veSF9dHWBindiZiUEb77EZ5HKmcMHMN85i4v')
    expect(toHex(decoded)).toBe('032ED4D80AC2383BDF25AFB282930CE26668D7FC0FCFE20CA620972009403662AB')
  })
})

test('encodes 123456789 with version byte of 0', () => {
  expect(api.codec.encode(Buffer.from('123456789'), {
    versions: [0],
    expectedLength: 9
  })).toBe('bhneTCVfMLTTJhd2Tmt')
})

test('multiple versions with no expected length should throw', () => {
  expect(() => {
    api.codec.decode('bhneTCVfMLTTJhd2Tmt', {
      versions: [0, 1]
    })
  }).toThrow('expectedLength is required because there are >= 2 possible versions')
})

test('attempting to decode data with length < 5 should throw', () => {
  expect(() => {
    api.codec.decode('1234', {
      versions: [0]
    })
  }).toThrow('invalid_input_size: decoded data must have length >= 5')
})

test('attempting to decode data with unexpected version should throw', () => {
  expect(() => {
    api.codec.decode('bhneTCVfMLTTJhd2Tmt', {
      versions: [2]
    })
  }).toThrow('version_invalid: version bytes do not match any of the provided version(s)')
})

test('invalid checksum should throw', () => {
  expect(() => {
    api.codec.decode('123456789', {
      versions: [0, 1]
    })
  }).toThrow('checksum_invalid')
})

test('empty payload should throw', () => {
  expect(() => {
    api.codec.decode('', {
      versions: [0, 1]
    })
  }).toThrow('invalid_input_size: decoded data must have length >= 5')
})

test('decode data', () => {
  expect(api.codec.decode('bhneTCVfMLTTJhd2Tmt', {
    versions: [0]
  })).toStrictEqual({
    version: [0],
    bytes: Buffer.from('123456789'),
    type: null
  })
})

test('decode data with expected length', function() {
  expect(api.codec.decode('bhneTCVfMLTTJhd2Tmt', {
      versions: [0],
      expectedLength: 9
    })
    ).toStrictEqual({
      version: [0],
      bytes: Buffer.from('123456789'),
      type: null
    })
})

test('decode data with wrong expected length should throw', function() {
  expect(() => {
    api.codec.decode('bhneTCVfMLTTJhd2Tmt', {
      versions: [0],
      expectedLength: 8
    })
  }).toThrow(
    'version_invalid: version bytes do not match any of the provided version(s)'
  )
  expect(() => {
    api.codec.decode('bhneTCVfMLTTJhd2Tmt', {
      versions: [0],
      expectedLength: 10
    })
  }).toThrow(
    'version_invalid: version bytes do not match any of the provided version(s)'
  )
})
