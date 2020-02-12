/** 
 * This module provides functions for constructing and validating
 * multisig transactions.
 * 
 * @module transactions
 */

import BigNumber from 'bignumber.js';

import {networkData} from  "./networks";
import {P2SH_P2WSH} from "./p2sh_p2wsh";
import {P2WSH} from "./p2wsh";
import {
  multisigRequiredSigners,
  multisigPublicKeys,
  multisigAddressType,
  multisigRedeemScript,
  multisigWitnessScript,
  generateMultisigFromRaw,
} from "./multisig";
import {
  validateMultisigSignature,
  signatureNoSighashType,
} from "./signatures";
import {validateMultisigInputs} from "./inputs";
import {validateOutputs} from "./outputs";
import {scriptToHex} from './script';
const bitcoin = require('bitcoinjs-lib');


/**
 * Create an unsigned bitcoin transaction based on the network, inputs
 * and outputs.
 *
 * Returns a [`Transaction`]{@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/types/transaction.d.ts|Transaction} object from bitcoinjs-lib.
 *
 * @param {module:networks.NETWORKS} network - bitcoin network
 * @param {module:inputs.MultisigTransactionInput[]} inputs - transaction inputs
 * @param {module:outputs.TransactionOutput[]} outputs - transaction outputs
 * @returns {Transaction} an unsigned bitcoinjs-lib Transaction object
 * @example
 * import {
 *   generateMultisigFromPublicKeys, TESTNET, P2SH,
 *   unsignedMultisigTransaction,
 * } from "unchained-bitcoin";
 * const multisig = generateMultisigFromPublicKeys(TESTNET, P2SH, 2, "03a...", "03b...");
 * const inputs = [
 *   {
 *     txid: "ae...",
 *     index: 0,
 *     multisig,
 *   },
 *   // other inputs...
 * ];
 * const outputs = [
 *   {
 *     address: "2N...",
 *     amountSats: 90000,
 *   },
 *   // other outputs...
 * ];
 * const unsignedTransaction = unsignedMultisigTransaction(TESTNET, inputs, outputs);
 * 
 */
export function unsignedMultisigTransaction(network, inputs, outputs) {
  let error = validateMultisigInputs(inputs);
  if (error) { throw new Error(error); }
  error = validateOutputs(network, outputs);
  if (error) { throw new Error(error); }
  const transactionBuilder = new bitcoin.TransactionBuilder();
  transactionBuilder.setVersion(1); // FIXME this depends on type...
  transactionBuilder.network = networkData(network);
  for (let inputIndex = 0; inputIndex < inputs.length; inputIndex += 1) {
    const input = inputs[inputIndex];
    transactionBuilder.addInput(input.txid, input.index);
  }
  for (let outputIndex = 0; outputIndex < outputs.length; outputIndex += 1) {
    const output = outputs[outputIndex];
    transactionBuilder.addOutput(output.address, BigNumber(output.amountSats).toNumber());
  }
  return transactionBuilder.buildIncomplete();
}

/**
 * Create a fully signed multisig transaction based on the unsigned
 * transaction, inputs, and their signatures.
 * 
 * @param {module:networks.NETWORKS} network - bitcoin network
 * @param {module:inputs.MultisigTransactionInput[]} inputs - multisig transaction inputs
 * @param {module:outputs.TransactionOutput[]} outputs - transaction outputs
 * @param {Object[]} transactionSignatures - array of transaction signatures, each an array of input signatures (1 per input)
 * @returns {Transaction} a signed {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/types/transaction.d.ts|Transaction} object
 * @example
 * import {
 *   generateMultisigFromPublicKeys, TESTNET, P2SH,
 *   signedMultisigTransaction,
 * } from "unchained-bitcoin";
 * const pubkey1 = "03a...";
 * const pubkey2 = "03b...";
 * const multisig = generateMultisigFromPublicKeys(TESTNET, P2SH, 2, pubkey1, pubkey2);
 * const inputs = [
 *   {
 *     txid: "ae...",
 *     index: 0,
 *     multisig,
 *   },
 *   // other inputs...
 * ];
 * const outputs = [
 *   {
 *     address: "2N...",
 *     amountSats: 90000,
 *   },
 *   // other outputs...
 * ];
 * const transactionSignatures = [
 *   // Each element is an array of signatures from a given key, one per input.
 *   [
 *     "301a...",
 *     // more, 1 per input
 *   ],
 *   [
 *     "301b...",
 *     // more, 1 per input
 *   ],
 *   // More transaction signatures if required, based on inputs
 * ];
 * const signedTransaction = signedMultisigTransaction(TESTNET, inputs, outputs, transactionSignatures)
 */
export function signedMultisigTransaction(network, inputs, outputs, transactionSignatures) {
  const unsignedTransaction = unsignedMultisigTransaction(network, inputs, outputs); // validates inputs & outputs
  if (!transactionSignatures || transactionSignatures.length === 0) { throw new Error("At least one transaction signature is required."); }

  transactionSignatures.forEach((transactionSignature, transactionSignatureIndex) => {
    if (transactionSignature.length < inputs.length) {
      throw new Error(`Insufficient input signatures for transaction signature ${transactionSignatureIndex + 1}: require ${inputs.length}, received ${transactionSignature.length}.`);
    }
  });

  const signedTransaction = bitcoin.Transaction.fromHex(unsignedTransaction.toHex()); // FIXME inefficient?
  for (let inputIndex=0; inputIndex < inputs.length; inputIndex++) {
    const input = inputs[inputIndex];

    const inputSignatures = transactionSignatures
          .map((transactionSignature) => transactionSignature[inputIndex])
          .filter((inputSignature) => Boolean(inputSignature));
    const requiredSignatures = multisigRequiredSigners(input.multisig);

    if (inputSignatures.length < requiredSignatures) {
      throw new Error(`Insufficient signatures for input  ${inputIndex + 1}: require ${requiredSignatures},  received ${inputSignatures.length}.`);
    }
    
    const inputSignaturesByPublicKey = {};
    inputSignatures.forEach((inputSignature) => {
      let publicKey;
      try {
        publicKey = validateMultisigSignature(network, inputs, outputs, inputIndex, inputSignature);
      } catch(e) {
        throw new Error(`Invalid signature for input ${inputIndex + 1}: ${inputSignature} (${e})`);
      }
      if (!publicKey) {
        throw new Error(`Invalid signature for input ${inputIndex + 1}: ${inputSignature}`);
      }
      if (inputSignaturesByPublicKey[publicKey]) {
        throw new Error(`Duplicate signature for input ${inputIndex + 1}: ${inputSignature}`);
      }
      inputSignaturesByPublicKey[publicKey] = inputSignature;
    });
    
    // Sort the signatures for this input by the index of their
    // corresponding public key within this input's redeem script.
    const publicKeys = multisigPublicKeys(input.multisig);
    const sortedSignatures = publicKeys
          .map((publicKey) => (inputSignaturesByPublicKey[publicKey]))
          .filter((signature) => signature ? signatureNoSighashType(signature) : signature); // FIXME why not filter out the empty sigs?

    if (multisigAddressType(input.multisig) === P2WSH) {
      const witness = multisigWitnessField(input.multisig, sortedSignatures);
      signedTransaction.setWitness(inputIndex, witness);
    } else     if (multisigAddressType(input.multisig) === P2SH_P2WSH) {
      const witness = multisigWitnessField(input.multisig, sortedSignatures);
      signedTransaction.setWitness(inputIndex, witness);
      const scriptSig = multisigRedeemScript(input.multisig);
      signedTransaction.ins[inputIndex].script = Buffer.from([scriptSig.output.length, ...scriptSig.output]);
    } else {
      const scriptSig = multisigScriptSig(input.multisig, sortedSignatures);
      signedTransaction.ins[inputIndex].script = scriptSig.input;
    }
  }

  return signedTransaction;
}

function multisigWitnessField(multisig, sortedSignatures) {
  const witness = [""].concat(sortedSignatures.map(s => signatureNoSighashType(s) +'01'));
  const witnessScript = multisigWitnessScript(multisig);
  witness.push(scriptToHex(witnessScript));
  return witness.map(wit => Buffer.from(wit, 'hex'));
}

function multisigScriptSig(multisig, signersInputSignatures) {
  const signatureOps = signersInputSignatures.map((signature) => (`${signatureNoSighashType(signature)}01`)).join(' '); // 01 => SIGHASH_ALL
  const inputScript = `OP_0 ${signatureOps}`;
  const inputScriptBuffer = bitcoin.script.fromASM(inputScript);
  const rawMultisig = bitcoin.payments.p2ms({
    network: multisig.network,
    output: Buffer.from(multisigRedeemScript(multisig).output, 'hex'),
    input: inputScriptBuffer,
  });
  return generateMultisigFromRaw(multisigAddressType(multisig), rawMultisig);
}
