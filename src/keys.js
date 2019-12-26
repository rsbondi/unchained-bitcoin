/**
 * This module provides validation of public keys and extended public keys.  Also it provides public key compression.
 * @module keys
 */

import {validateHex} from "./utils";
import {NETWORKS, networkData} from "./networks";
import {ECPair} from "bitcoinjs-lib"

const bip32 = require('bip32');
const bs58check = require('bs58check');

export const extendedPublicKeyVersions = {
  xpub: "0488b21e",
  ypub: "049d7cb2",
  zpub: "04b2430c",
  Ypub: "0295b43f",
  Zpub: "02aa7ed3",
  tpub: "043587cf",
  upub: "044a5262",
  vpub: "045f1cf6",
  Upub: "024289ef",
  Vpub: "02575483"
}

function validatePrefix(prefix, prefixType) {
  if (!~Object.keys(extendedPublicKeyVersions).indexOf(prefix)) {
    return `Invalid ${prefixType} version for extended public key conversion`;
  }
  return null;
}

/**
 * result object for extended public key conversion
 * @typedef ConvertedExtendedPublicKey
 * @static
 * @property {string} extendedPublicKey - the converted key if successfully converted, original key if error
 * @property {string} [message] - additional information about the conversion
 * @property {string} [error] - conversion error message
 */

/**
 * Convert an extended public key between formats
 * @param {string} extendedPublicKey - the extended public key to convert
 * @param {string} targetPrefix - the target format to convert to
 * @example
 * const tpub = extendedPublicKeyConvert("xpub6CCH...", "tpub");
 * if (tpub.error) {
 *   // handle
 * } else if (tpub.message === '') {
 *   // no conversion was needed
 * } else {
 *   console.log(tpub.extendedPublicKey, tpub.message)
 *   // tpubDCZv...
 *   // Your extended public key has been converted from xpub to tpub
 * }
 * @returns {module:keys.ConvertedExtendedPublicKey}
 */
export function extendedPublicKeyConvert(extendedPublicKey, targetPrefix) {
  const targetError = validatePrefix(targetPrefix, 'target')
  if (targetError !== null) return {extendedPublicKey, error:targetError};

  const sourcePrefix = extendedPublicKey.slice(0, 4);
  const sourceError = validatePrefix(sourcePrefix, 'source')
  if (sourceError !== null) return {extendedPublicKey, error:sourceError};

  try {
    const decodedExtendedPublicKey = bs58check.decode(extendedPublicKey.trim());
    const extendedPublicKeyNoPrefix = decodedExtendedPublicKey.slice(4);
    const extendedPublicKeyNewPrefix = Buffer.concat([Buffer.from(extendedPublicKeyVersions[targetPrefix],'hex'), extendedPublicKeyNoPrefix]);
    return {
      extendedPublicKey: bs58check.encode(extendedPublicKeyNewPrefix),
      message: `Your extended public key has been converted from ${sourcePrefix} to ${targetPrefix}`,
      error: ""
    }
  } catch (err) {
    return {
      extendedPublicKey,
      error: "Unable to convert extended public key: "+err.message
    };
  }
}

/**
 * Perform conversion to xpub or tpub based on the bitcoin network
 * additional validation is performed on the converted extended public key
 * @param {string} extendedPublicKey - the extended public key to convert
 * @param {string} network - the bitcoin network
 * @example
 * const xpub = convertAndValidateExtendedPublicKey('tpubDCZv...', NETWORKS.MAINNET)
 * if (xpub.error) {
 *   // handle
 * } else if (xpub.message === '') {
 *   // no conversion was needed
 * } else {
 *   console.log(xpub.extendedPublicKey, xpub.message)
 *   // tpubDCZv...
 *   // Your extended public key has been converted from tpub to xpub
 * }
 * @returns {module:keys.ConvertedExtendedPublicKey}
 */
export function convertAndValidateExtendedPublicKey(extendedPublicKey, network) {
  const targetPrefix = network === NETWORKS.TESTNET ? 'tpub' : 'xpub'
  const preliminaryErrors = preExtendedPublicKeyValidation(extendedPublicKey, network);
  if (preliminaryErrors !== '') {
    return {extendedPublicKey, error: preliminaryErrors};
  } else {
    const networkError = extendedPublicKeyNetworkValidateion(extendedPublicKey, network)
    if (networkError === '') {
      const extendedPublicKeyValidation = validateExtendedPublicKey(extendedPublicKey, network);
      if (extendedPublicKeyValidation === '')
        return {extendedPublicKey, message:"", error: ""}; // valid for network, use it
      // else convert and validate below
    }
  }

  const convertedExtendedPublicKey = extendedPublicKeyConvert(extendedPublicKey, targetPrefix);
  if (convertedExtendedPublicKey.extendedPublicKey !== extendedPublicKey) { // a conversion happended
    const extendedPublicKeyValidation = validateExtendedPublicKey(convertedExtendedPublicKey.extendedPublicKey, network);
    if (extendedPublicKeyValidation === '') return convertedExtendedPublicKey;
    else return {extendedPublicKey, error: extendedPublicKeyValidation}
  } else return convertedExtendedPublicKey;

}

function extendedPublicKeyNetworkValidateion(extendedPublicKey, network) {
  let requiredPrefix = "'xpub'";
  if (network === NETWORKS.TESTNET) {
    requiredPrefix += " or 'tpub'";
  }
  const notXpubError = `Extended public key must begin with ${requiredPrefix}.`;
  const prefix = extendedPublicKey.slice(0, 4);
  if (! (prefix === 'xpub' || (network === NETWORKS.TESTNET && prefix === 'tpub'))) {
    return notXpubError;
  }
  return '';
}

function preExtendedPublicKeyValidation(extendedPublicKey, network) {
  if (extendedPublicKey === null || extendedPublicKey === undefined || extendedPublicKey === '') {
    return "Extended public key cannot be blank.";
  }

  if (extendedPublicKey.length < 111) {
    return "Extended public key length is too short.";
  }

  return '';

}

/**
 * Provide validation messages for an extended public key.
 * @param {string} inputString - base58 encoded extended public key
 * @param {module:networks.NETWORKS} network  - bitcoin network
 * @example
 * const key = "apub6CCHViYn5VzKSmKD9cK9LBDPz9wBLV7owXJcNDioETNvhqhVtj3ABnVUERN9aV1RGTX9YpyPHnC4Ekzjnr7TZthsJRBiXA4QCeXNHEwxLab";
 * const validationError = validateExtendedPublicKey(key, NETWORKS.TESTNET);
 * console.log(validationError); // Extended public key must begin with 'xpub' or 'tpub'."
 * @returns {string} empty if valid or corresponding validation message
 */
export function validateExtendedPublicKey(inputString, network) {
  const preliminaryErrors = preExtendedPublicKeyValidation(inputString, network);
  if (preliminaryErrors !== '') {
    return preliminaryErrors;
  }

  const networkError = extendedPublicKeyNetworkValidateion(inputString, network);
  if (networkError !== '') {
    return networkError;
  }

  try {
    bip32.fromBase58(inputString, networkData(network));
  } catch (e) {
    return `Invalid extended public key: ${e}`;
  }

  return '';

}

/**
 * Provide validation messages for a public key.
 * @param {string} inputString - hex public key string
 * @example
 * const validationError = validatePublicKey("03b32dc780fba98db25b4b72cf2b69da228f5e10ca6aa8f46eabe7f9fe22c994ee"); // result empty, valid key
 * @returns {string} empty if valid or corresponding validation message
 */
export function validatePublicKey(inputString) {
  if (inputString === null || inputString === undefined || inputString === '') {
    return "Public key cannot be blank.";
  }

  const error = validateHex(inputString);
  if (error !== '') { return error; }

  try {
    ECPair.fromPublicKey(Buffer.from(inputString, 'hex'));
  } catch (e) {
    return `Invalid public key ${e}.`;
  }

  return '';
}

/**
 * Compresses a public key.
 * @param {string} publicKey - the hex public key to compress
 * @example
 * const compressed = compressPublicKey("04b32dc780fba98db25b4b72cf2b69da228f5e10ca6aa8f46eabe7f9fe22c994ee6e43c09d025c2ad322382347ec0f69b4e78d8e23c8ff9aa0dd0cb93665ae83d5");
 * console.log(compressed); // 03b32dc780fba98db25b4b72cf2b69da228f5e10ca6aa8f46eabe7f9fe22c994ee
 * @returns {string} compressed public key
 */
export function compressPublicKey(publicKey) {
  // validate Public Key Length
  // validate Public Key Structure
  const pubkeyBuffer = Buffer.from(publicKey, 'hex');
  // eslint-disable-next-line no-bitwise
  const prefix = (pubkeyBuffer[64] & 1) !== 0 ? 0x03 : 0x02;
  const prefixBuffer = Buffer.alloc(1);
  prefixBuffer[0] = prefix;
  return Buffer.concat([prefixBuffer, pubkeyBuffer.slice(1, 1 + 32)]).toString('hex');
}
