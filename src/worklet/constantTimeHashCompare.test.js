import sodium from 'sodium-native'

import { constantTimeHashCompare } from './constantTimeHashCompare'

jest.mock('sodium-native', () => ({
  crypto_secretbox_KEYBYTES: 32,
  sodium_memcmp: jest.fn()
}))

describe('constantTimeHashCompare', () => {
  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('with hex encoding (default)', () => {
    it('should return true for equal hashes', () => {
      const hash = Buffer.alloc(32, 'a').toString('hex')
      sodium.sodium_memcmp.mockReturnValue(true)

      const result = constantTimeHashCompare(hash, hash)

      expect(result).toBe(true)
      expect(sodium.sodium_memcmp).toHaveBeenCalledTimes(1)
      expect(sodium.sodium_memcmp).toHaveBeenCalledWith(
        Buffer.from(hash, 'hex'),
        Buffer.from(hash, 'hex')
      )
    })

    it('should return false for different hashes', () => {
      const hash1 = Buffer.alloc(32, 'a').toString('hex')
      const hash2 = Buffer.alloc(32, 'b').toString('hex')
      sodium.sodium_memcmp.mockReturnValue(false)

      const result = constantTimeHashCompare(hash1, hash2)

      expect(result).toBe(false)
      expect(sodium.sodium_memcmp).toHaveBeenCalledTimes(1)
    })

    it('should return false for invalid hash length (too short)', () => {
      const validHash = Buffer.alloc(32, 'a').toString('hex')
      const shortHash = Buffer.alloc(16, 'b').toString('hex')

      const result = constantTimeHashCompare(validHash, shortHash)

      expect(result).toBe(false)
      expect(sodium.sodium_memcmp).not.toHaveBeenCalled()
    })

    it('should return false for invalid hash length (too long)', () => {
      const validHash = Buffer.alloc(32, 'a').toString('hex')
      const longHash = Buffer.alloc(64, 'b').toString('hex')

      const result = constantTimeHashCompare(validHash, longHash)

      expect(result).toBe(false)
      expect(sodium.sodium_memcmp).not.toHaveBeenCalled()
    })
  })

  describe('with base64 encoding', () => {
    it('should return true for equal base64-encoded values', () => {
      const value = Buffer.alloc(32, 'x').toString('base64')
      sodium.sodium_memcmp.mockReturnValue(true)

      const result = constantTimeHashCompare(value, value, 'base64')

      expect(result).toBe(true)
      expect(sodium.sodium_memcmp).toHaveBeenCalledTimes(1)
      expect(sodium.sodium_memcmp).toHaveBeenCalledWith(
        Buffer.from(value, 'base64'),
        Buffer.from(value, 'base64')
      )
    })

    it('should return false for different base64-encoded values', () => {
      const value1 = Buffer.alloc(32, 'x').toString('base64')
      const value2 = Buffer.alloc(32, 'y').toString('base64')
      sodium.sodium_memcmp.mockReturnValue(false)

      const result = constantTimeHashCompare(value1, value2, 'base64')

      expect(result).toBe(false)
      expect(sodium.sodium_memcmp).toHaveBeenCalledTimes(1)
    })

    it('should return false for invalid base64 length', () => {
      const validValue = Buffer.alloc(32, 'a').toString('base64')
      const shortValue = Buffer.alloc(16, 'b').toString('base64')

      const result = constantTimeHashCompare(validValue, shortValue, 'base64')

      expect(result).toBe(false)
      expect(sodium.sodium_memcmp).not.toHaveBeenCalled()
    })
  })

  describe('input validation', () => {
    it('should return false for non-string inputs', () => {
      const validHash = Buffer.alloc(32, 'a').toString('hex')

      expect(constantTimeHashCompare(null, validHash)).toBe(false)
      expect(constantTimeHashCompare(validHash, null)).toBe(false)
      expect(constantTimeHashCompare(undefined, validHash)).toBe(false)
      expect(constantTimeHashCompare(123, validHash)).toBe(false)
      expect(constantTimeHashCompare({}, validHash)).toBe(false)
      expect(sodium.sodium_memcmp).not.toHaveBeenCalled()
    })

    it('should return false when both values have invalid length', () => {
      const shortHash1 = Buffer.alloc(16, 'a').toString('hex')
      const shortHash2 = Buffer.alloc(16, 'b').toString('hex')

      const result = constantTimeHashCompare(shortHash1, shortHash2)

      expect(result).toBe(false)
      expect(sodium.sodium_memcmp).not.toHaveBeenCalled()
    })
  })

  it('should use constant-time comparison via sodium.sodium_memcmp', () => {
    const hash1 = Buffer.alloc(32, 'x').toString('hex')
    const hash2 = Buffer.alloc(32, 'y').toString('hex')
    sodium.sodium_memcmp.mockReturnValue(false)

    constantTimeHashCompare(hash1, hash2)

    expect(sodium.sodium_memcmp).toHaveBeenCalledWith(
      expect.any(Buffer),
      expect.any(Buffer)
    )
  })
})
