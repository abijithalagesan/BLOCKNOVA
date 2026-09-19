import fs from "node:fs";
import { AbiCoder, Contract, JsonRpcProvider, Wallet } from "ethers";

const resultPath = process.argv[2];
if (!resultPath) throw new Error("usage: npx tsx scripts/issue_attestation.ts result.json");
const rpcUrl = process.env.ETHEREUM_RPC_URL;
const privateKey = process.env.ATTESTATION_PRIVATE_KEY;
const easAddress = process.env.EAS_ADDRESS;
const schemaUid = process.env.BLOCKNOVA_SCHEMA_UID;
const registryAddress = process.env.BLOCKNOVA_REGISTRY_ADDRESS;
if (!rpcUrl || !privateKey || !easAddress || !schemaUid || !registryAddress) {
  throw new Error("real attestation is not configured: require ETHEREUM_RPC_URL, ATTESTATION_PRIVATE_KEY, EAS_ADDRESS, BLOCKNOVA_SCHEMA_UID, BLOCKNOVA_REGISTRY_ADDRESS");
}

const result = JSON.parse(fs.readFileSync(resultPath, "utf8"));
const provider = new JsonRpcProvider(rpcUrl);
const signer = new Wallet(privateKey, provider);
const coder = AbiCoder.defaultAbiCoder();
const observedThrough = Math.floor(Date.parse(result.observedThrough ?? new Date().toISOString()) / 1000);
const expiresAt = Math.floor(Date.parse(result.expiresAt ?? new Date(Date.now() + 30 * 86400000).toISOString()) / 1000);
const encoded = coder.encode(["address", "string", "uint256", "uint256", "uint256", "uint256", "uint256", "bytes32", "uint64", "uint64"], [result.address, result.version ?? "1.0", result.riskScore, result.riskVector.directThreat, result.riskVector.indirectExposure, result.riskVector.permissionExposure, result.dataQuality, `0x${result.evidenceRoot}`, observedThrough, expiresAt]);
const eas = new Contract(easAddress, ["function attest(bytes32 schema, (address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint16 value) request) payable returns (bytes32)"], signer);
const tx = await eas.attest(schemaUid, { recipient: result.address, expirationTime: expiresAt, revocable: true, refUID: "0x" + "00".repeat(32), data: encoded, value: 0 });
const receipt = await tx.wait();
const uid = await eas.attest.staticCall(schemaUid, { recipient: result.address, expirationTime: expiresAt, revocable: true, refUID: "0x" + "00".repeat(32), data: encoded, value: 0 });
const registry = new Contract(registryAddress, ["function registerAttestation(address subject,bytes32 uid)"], signer);
await (await registry.registerAttestation(result.address, uid)).wait();
console.log(JSON.stringify({ subject: result.address, riskScore: result.riskScore, evidenceRoot: result.evidenceRoot, attestationUid: uid, transactionHash: receipt.hash }));
