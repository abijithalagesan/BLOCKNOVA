import { Contract, JsonRpcProvider } from "ethers";

const subject = process.argv[2];
if (!subject) throw new Error("usage: npx tsx scripts/verify_attestation.ts <subject>");
const rpcUrl = process.env.ETHEREUM_RPC_URL;
const easAddress = process.env.EAS_ADDRESS;
const registryAddress = process.env.BLOCKNOVA_REGISTRY_ADDRESS;
const schemaUid = process.env.BLOCKNOVA_SCHEMA_UID;
const trustedIssuer = process.env.BLOCKNOVA_TRUSTED_ISSUER?.toLowerCase();
if (!rpcUrl || !easAddress || !registryAddress || !schemaUid || !trustedIssuer) {
  throw new Error("real verification is not configured: require ETHEREUM_RPC_URL, EAS_ADDRESS, BLOCKNOVA_REGISTRY_ADDRESS, BLOCKNOVA_SCHEMA_UID, BLOCKNOVA_TRUSTED_ISSUER");
}
const provider = new JsonRpcProvider(rpcUrl);
const registry = new Contract(registryAddress, ["function latestAttestation(address subject) view returns (bytes32)"], provider);
const uid = await registry.latestAttestation(subject);
if (uid === "0x" + "00".repeat(32)) {
  console.log(JSON.stringify({ subject, status: "NO_ATTESTATION" }));
  process.exit(0);
}
const eas = new Contract(easAddress, ["function getAttestation(bytes32 uid) view returns (tuple(bytes32 uid,bytes32 schema,uint64 time,uint64 expirationTime,bool revocable,bool revoked,address refUID,address recipient,address attester,bytes data))"], provider);
const attestation = await eas.getAttestation(uid);
const status = attestation.revoked ? "REVOKED" : Number(attestation.expirationTime) <= Math.floor(Date.now() / 1000) ? "EXPIRED" : attestation.schema.toLowerCase() !== schemaUid.toLowerCase() ? "WRONG_SCHEMA" : attestation.attester.toLowerCase() !== trustedIssuer ? "WRONG_ISSUER" : "CURRENT";
console.log(JSON.stringify({ subject, uid, status, issuer: attestation.attester, schema: attestation.schema, expirationTime: Number(attestation.expirationTime) }));
