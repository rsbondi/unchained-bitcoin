import { validateExtendedPublicKey, validatePublicKey, compressPublicKey,
         extendedPublicKeyConvert, convertAndValidateExtendedPublicKey } from './keys'
import { NETWORKS } from './networks';

import { emptyValues, keysCompressedUncompressed, validXpub, validTpub, extendedPublicKeyConversions } from './test_constants';

describe('Test key validation library', () => {
    describe("Test validateExtendedPublicKey", () => {
        it('should properly report the validation of an empty key value', () => {
            emptyValues.forEach(k => {
                const result = validateExtendedPublicKey(k);
                expect(result).toBe("Extended public key cannot be blank.");
            });
        });

        describe("Test invalid prefixes", () =>{
            it('should properly report the validation of an improper key prefix on mainnet', () => {
                const key = "apub6CCHViYn5VzKSmKD9cK9LBDPz9wBLV7owXJcNDioETNvhqhVtj3ABnVUERN9aV1RGTX9YpyPHnC4Ekzjnr7TZthsJRBiXA4QCeXNHEwxLab";
                const result = validateExtendedPublicKey(key);
                expect(result).toBe("Extended public key must begin with 'xpub'.");
            });

            it('should properly report the validation of an improper key prefix on testnet', () => {
                const key = "apub6CCHViYn5VzKSmKD9cK9LBDPz9wBLV7owXJcNDioETNvhqhVtj3ABnVUERN9aV1RGTX9YpyPHnC4Ekzjnr7TZthsJRBiXA4QCeXNHEwxLab";
                const result = validateExtendedPublicKey(key, NETWORKS.TESTNET);
                expect(result).toBe("Extended public key must begin with 'xpub' or 'tpub'.");
            });
        });


        it("should properly report the validation of a key of insufficient length", () => {
            const key = "xpub";
            const result = validateExtendedPublicKey(key);
            expect(result).toBe("Extended public key length is too short.");
        });

        describe("Test invalid keys", () =>{
            const invalid = /^Invalid extended public key/
            it("should properly report the validation of an invalid xpub key on mainnet", () => {
                const xpub = "xpub6CCHV1Yn5VzKSmKD9cK9LBDPz9wBLV7owXJcNDioETNvhqhVtj3ABnVUERN9aV1RGTX9YpyPHnC4Ekzjnr7TZthsJRBiXA4QCeXNHEwxLab";
                const result = validateExtendedPublicKey(xpub, NETWORKS.MAINNET);
                expect(invalid.test(result)).toBe(true);
            });

            it("should properly report the validation of an invalid tpub key on testnet", () => {
                const tpub = "tpubDCZvixNTnmwmiZW4boJEY6YmKH2qKscsV9tuimmwaN8pT8NCxwtFLEAJUTSw6yxf4N44AQVFpt26vwVMBhxhTLAAN1w2Cgidnc7n3JVnBDH";
                const result = validateExtendedPublicKey(tpub, NETWORKS.TESTNET);
                expect(invalid.test(result)).toBe(true);
            });
        });

        describe("Test valid keys", () =>{
            it('should not provide a validation message for a valid xpub key on mainnet', () => {
                const result = validateExtendedPublicKey(validXpub, NETWORKS.MAINNET);
                expect(result).toBe("");
            });

            it('should not provide a validation message for a valid tpub key on testnet', () => {
                const result = validateExtendedPublicKey(validTpub, NETWORKS.TESTNET);
                expect(result).toBe("");
            });
        });

    });

    describe("Test validatePublicKey", () => {
        it('should properly report the validation of using an empty key value', () => {
            emptyValues.forEach(b => {
                const result = validatePublicKey(b);
                expect(result).toBe("Public key cannot be blank.");
            });
        });

        it("shold report invalid hex", () => {
            const bad = ["aaa", "ffaz"]
            bad.forEach(hex => {
                const result = validatePublicKey(hex);
                expect(result).not.toBe(""); // actual values test in utils module
            });
        });

        it("should report invalid key", () => {
            const bad = ["aaaa", "0000000000000000"]
            const invalid = /^Invalid public key/

            bad.forEach(key => {
                const result = validatePublicKey(key);
                expect(invalid.test(result)).toBe(true);
            });
        });

        it('should not provide a validation message for a valid compressed public key', () => {
            keysCompressedUncompressed.forEach(key => {
                const result = validatePublicKey(key.compressed);
                expect(result).toBe("")
            })
        });

        it('should not provide a validation message for a valid uncompressed public key', () => {
            keysCompressedUncompressed.forEach(key => {
                const result = validatePublicKey(key.uncompressed);
                expect(result).toBe("")
            })
        });
    });

    describe("Test compressPublicKey", () => {
        it("should properly compress public key", () => {
            keysCompressedUncompressed.forEach(k => {
                const result = compressPublicKey(k.uncompressed);
                expect(result).toBe(k.compressed)
            });
        });
    });

    describe("Test extendedPublicKeyConvert", () => {
        describe("Test converting to xpub", () => {
            it("should properly convert extended public key from tpub to xpub", () => {
                const tpub = extendedPublicKeyConvert(extendedPublicKeyConversions.tpub, 'xpub')
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
                expect(tpub.message).toBe("Your extended public key has been converted from tpub to xpub")
            });

            it("should properly convert extended public key from ypub to xpub", () => {
                const ypub = extendedPublicKeyConvert(extendedPublicKeyConversions.ypub, 'xpub')
                expect(ypub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
                expect(ypub.message).toBe("Your extended public key has been converted from ypub to xpub")
            });

            it("should properly convert extended public key from zpub to xpub", () => {
                const zpub = extendedPublicKeyConvert(extendedPublicKeyConversions.zpub, 'xpub')
                expect(zpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
            });

            it("should properly convert extended public key from Ypub to xpub", () => {
                const Ypub = extendedPublicKeyConvert(extendedPublicKeyConversions.Ypub, 'xpub')
                expect(Ypub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
            });

            it("should properly convert extended public key from Zpub to xpub", () => {
                const Zpub = extendedPublicKeyConvert(extendedPublicKeyConversions.Zpub, 'xpub')
                expect(Zpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
            });

            it("should properly convert extended public key from upub to xpub", () => {
                const upub = extendedPublicKeyConvert(extendedPublicKeyConversions.upub, 'xpub')
                expect(upub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
            });

            it("should properly convert extended public key from vpub to xpub", () => {
                const vpub = extendedPublicKeyConvert(extendedPublicKeyConversions.vpub, 'xpub')
                expect(vpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
            });

            it("should properly convert extended public key from Upub to xpub", () => {
                const Upub = extendedPublicKeyConvert(extendedPublicKeyConversions.Upub, 'xpub')
                expect(Upub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
            });

            it("should properly convert extended public key from Vpub to xpub", () => {
                const Vpub = extendedPublicKeyConvert(extendedPublicKeyConversions.Vpub, 'xpub')
                expect(Vpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
            });

        });

        describe("Test converting to tpub", () => {
            it("should properly convert extended public key from xpub to tpub", () => {
                const xpub = extendedPublicKeyConvert(extendedPublicKeyConversions.xpub, 'tpub')
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

            it("should properly convert extended public key from ypub to tpub", () => {
                const ypub = extendedPublicKeyConvert(extendedPublicKeyConversions.ypub, 'tpub')
                expect(ypub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });
            it("should properly convert extended public key from zpub to tpub", () => {
                const zpub = extendedPublicKeyConvert(extendedPublicKeyConversions.zpub, 'tpub')
                expect(zpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

            it("should properly convert extended public key from Ypub to tpub", () => {
                const Ypub = extendedPublicKeyConvert(extendedPublicKeyConversions.Ypub, 'tpub')
                expect(Ypub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

            it("should properly convert extended public key from Zpub to tpub", () => {
                const Zpub = extendedPublicKeyConvert(extendedPublicKeyConversions.Zpub, 'tpub')
                expect(Zpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

            it("should properly convert extended public key from upub to tpub", () => {
                const upub = extendedPublicKeyConvert(extendedPublicKeyConversions.upub, 'tpub')
                expect(upub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

            it("should properly convert extended public key from vpub to tpub", () => {
                const vpub = extendedPublicKeyConvert(extendedPublicKeyConversions.vpub, 'tpub')
                expect(vpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

            it("should properly convert extended public key from Upub to tpub", () => {
                const Upub = extendedPublicKeyConvert(extendedPublicKeyConversions.Upub, 'tpub')
                expect(Upub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

            it("should properly convert extended public key from Vpub to tpub", () => {
                const Vpub = extendedPublicKeyConvert(extendedPublicKeyConversions.Vpub, 'tpub')
                expect(Vpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub)
            });

        });


        describe("Test conversion prefix format validation", () => {
            it("should properly validate extended public with invalid target format", () => {
                const xpub = extendedPublicKeyConvert(extendedPublicKeyConversions.xpub, 'apub')
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub)
                expect(xpub.error).toBe("Invalid target version for extended public key conversion")
            });

            it("should properly validate extended public with invalid source format", () => {
                const bad = 'a'+extendedPublicKeyConversions.xpub.slice(1)
                const xpub = extendedPublicKeyConvert(bad, 'tpub')
                expect(xpub.extendedPublicKey).toBe(bad)
                expect(xpub.error).toBe("Invalid source version for extended public key conversion")
            });

        });
    });

    describe("Test convertAndValidateExtendedPublicKey", () => {
        describe("Test converting to xpub for mainnet", () => {
            it("should properly return source xpub when valid for mainnet", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.xpub, NETWORKS.MAINNET)
                expect(xpub.message).toBe('');
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when tpub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.tpub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from tpub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when ypub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.ypub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from ypub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when zpub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.zpub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from zpub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when Ypub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Ypub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from Ypub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when Zpub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Zpub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from Zpub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when upub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.upub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from upub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when vpub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.vpub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from vpub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when vpub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.vpub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from vpub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when Upub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Upub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from Upub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });

            it("should properly return converted xpub and message when Vpub provided", () => {
                const xpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Vpub, NETWORKS.MAINNET)
                expect(xpub.message).toBe("Your extended public key has been converted from Vpub to xpub");
                expect(xpub.extendedPublicKey).toBe(extendedPublicKeyConversions.xpub);
            });
        });

        describe("Test converting to tpub for testnet", () => {
            it("should properly return source tpub when valid for testnet", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.tpub, NETWORKS.TESTNET)
                expect(tpub.message).toBe('');
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when xpub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.xpub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from xpub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when ypub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.ypub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from ypub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when zpub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.zpub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from zpub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when Ypub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Ypub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from Ypub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when Zpub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Zpub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from Zpub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when upub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.upub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from upub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when vpub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.vpub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from vpub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when vpub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.vpub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from vpub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when Upub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Upub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from Upub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });

            it("should properly return converted tpub and message when Vpub provided", () => {
                const tpub = convertAndValidateExtendedPublicKey(extendedPublicKeyConversions.Vpub, NETWORKS.TESTNET)
                expect(tpub.message).toBe("Your extended public key has been converted from Vpub to tpub");
                expect(tpub.extendedPublicKey).toBe(extendedPublicKeyConversions.tpub);
            });
        });

        describe("Test validation when attempting to convert to xpub for mainnet", () => {
            it("should properly return validation message when invalid source prefix provided", () => {
                const bad = 'a'+extendedPublicKeyConversions.xpub.slice(1)
                const xpub = convertAndValidateExtendedPublicKey(bad, NETWORKS.MAINNET)
                expect(xpub.error).toBe("Invalid source version for extended public key conversion");
                expect(xpub.extendedPublicKey).toBe(bad);
            });

            describe("Test pass through validation when attempting to convert to xpub", () => {
                it("should properly validate an invalid extended public key provided", () => {
                    const bad = extendedPublicKeyConversions.xpub.slice(0, extendedPublicKeyConversions.xpub.length - 2)+'xx'
                    const xpub = convertAndValidateExtendedPublicKey(bad, NETWORKS.MAINNET)
                    expect(xpub.error).toMatch(/^Unable to convert extended public key:.+/); // remainder of message from another lib
                    expect(xpub.extendedPublicKey).toBe(bad);
                });

                it('should properly report the validation of an empty key value', () => {
                    emptyValues.forEach(empty => {
                        const xpub = convertAndValidateExtendedPublicKey(empty, NETWORKS.MAINNET)
                        expect(xpub.error).toBe("Extended public key cannot be blank.");
                        expect(xpub.extendedPublicKey).toBe(empty);
                        });
                });

                it("should properly report the validation of a key of insufficient length", () => {
                    const key = "xpub";
                    const xpub = convertAndValidateExtendedPublicKey(key, NETWORKS.MAINNET);
                    expect(xpub.error).toBe("Extended public key length is too short.");
                    expect(xpub.extendedPublicKey).toBe(key);
                });

             });
        });


        describe("Test validation when attempting to convert to tpub for testnet", () => {
            it("should properly return validation message when invalid source prefix provided", () => {
                const bad = 'a'+extendedPublicKeyConversions.tpub.slice(1)
                const tpub = convertAndValidateExtendedPublicKey(bad, NETWORKS.TESTNET)
                expect(tpub.error).toBe("Invalid source version for extended public key conversion");
                expect(tpub.extendedPublicKey).toBe(bad);
            });

            describe("Test pass through validation when attempting to convert to tpub", () => {
                it("should properly validate an invalid extended public key provided", () => {
                    const bad = extendedPublicKeyConversions.tpub.slice(0, extendedPublicKeyConversions.tpub.length - 2)+'xx'
                    const tpub = convertAndValidateExtendedPublicKey(bad, NETWORKS.TESTNET)
                    expect(tpub.error).toMatch(/^Unable to convert extended public key:.+/); // remainder of message from another lib
                    expect(tpub.extendedPublicKey).toBe(bad);
                });

                it('should properly report the validation of an empty key value', () => {
                    emptyValues.forEach(empty => {
                        const tpub = convertAndValidateExtendedPublicKey(empty, NETWORKS.TESTNET)
                        expect(tpub.error).toBe("Extended public key cannot be blank.");
                        expect(tpub.extendedPublicKey).toBe(empty);
                        });
                });

                it("should properly report the validation of a key of insufficient length", () => {
                    const key = "tpub";
                    const tpub = convertAndValidateExtendedPublicKey(key, NETWORKS.TESTNET);
                    expect(tpub.error).toBe("Extended public key length is too short.");
                    expect(tpub.extendedPublicKey).toBe(key);
                });

             });
        });
    });

});