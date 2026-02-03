import sodium from 'sodium-native'

/**
 * Performs constant-time comparison of two encoded 32-byte values.
 * Uses sodium.sodium_memcmp() to prevent timing side-channel attacks.
 *
 * @param {string} value1 - First encoded value (32 bytes when decoded)
 * @param {string} value2 - Second encoded value (32 bytes when decoded)
 * @param {string} [encoding='hex'] - Encoding format ('hex' or 'base64')
 * @returns {boolean} - true if values are equal, false otherwise
 */
export const constantTimeHashCompare = (value1, value2, encoding = 'hex') => {
  if (typeof value1 !== 'string' || typeof value2 !== 'string') {
    return false
  }

  const buffer1 = Buffer.from(value1, encoding)
  const buffer2 = Buffer.from(value2, encoding)

  if (
    buffer1.length !== sodium.crypto_secretbox_KEYBYTES ||
    buffer2.length !== sodium.crypto_secretbox_KEYBYTES
  ) {
    return false
  }

  return sodium.sodium_memcmp(buffer1, buffer2)
}
