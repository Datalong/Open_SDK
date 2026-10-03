import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  issueOrganizationCredential,
  verifyOrganizationCredential,
  createAgentCard,
  signAgentCard,
} from '../src/index.js';

describe('W3C Verifiable Credentials (VC) Core', () => {
  it('issues and cryptographically verifies an organization credential', () => {
    const issuerKp = generateKeyPair();
    const agentKp = generateKeyPair();

    // 1. 企业根组织对子 Agent 签发担保凭据
    const vc = issueOrganizationCredential(
      {
        agentDid: agentKp.address,
        issuerDid: issuerKp.address,
        organizationName: 'Datalong Official AI Lab',
        organizationDomain: 'datalong.ai',
        verifiedLevel: 'official',
        badge: 'gold_v',
        capabilitiesEndorsed: ['code_generation', 'security_audit'],
      },
      issuerKp.privateKey
    );

    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(vc.issuer).toBe(issuerKp.address);
    expect(vc.credentialSubject.id).toBe(agentKp.address);
    expect(vc.credentialSubject.badge).toBe('gold_v');

    // 2. 离线校验凭证
    const check = verifyOrganizationCredential(vc);
    expect(check.valid).toBe(true);
    expect(check.organizationName).toBe('Datalong Official AI Lab');
    expect(check.badge).toBe('gold_v');
    expect(check.subjectDid).toBe(agentKp.address);
  });

  it('rejects tampered credential content', () => {
    const issuerKp = generateKeyPair();
    const agentKp = generateKeyPair();

    const vc = issueOrganizationCredential(
      {
        agentDid: agentKp.address,
        issuerDid: issuerKp.address,
        organizationName: 'Legitimate Corp',
        organizationDomain: 'legit.com',
      },
      issuerKp.privateKey
    );

    // 恶意篡改组织名称
    vc.credentialSubject.organizationName = 'Hacked Impostor Corp';

    const check = verifyOrganizationCredential(vc);
    expect(check.valid).toBe(false);
    expect(check.error).toContain('signature verification failed');
  });

  it('rejects expired credential', () => {
    const issuerKp = generateKeyPair();
    const agentKp = generateKeyPair();

    const vc = issueOrganizationCredential(
      {
        agentDid: agentKp.address,
        issuerDid: issuerKp.address,
        organizationName: 'Short-lived Corp',
        organizationDomain: 'corp.com',
        validityDays: -1, // 已过期
      },
      issuerKp.privateKey
    );

    const check = verifyOrganizationCredential(vc);
    expect(check.valid).toBe(false);
    expect(check.error).toContain('expired');
  });

  it('enforces trusted issuer white-listing and revocation lists', () => {
    const issuerKp = generateKeyPair();
    const rogueIssuerKp = generateKeyPair();
    const agentKp = generateKeyPair();

    const rogueVc = issueOrganizationCredential(
      {
        agentDid: agentKp.address,
        issuerDid: rogueIssuerKp.address,
        organizationName: 'Fake Org',
        organizationDomain: 'fake.com',
      },
      rogueIssuerKp.privateKey
    );

    // 1. 信任白名单拦截
    const untrustedCheck = verifyOrganizationCredential(rogueVc, {
      trustedIssuers: [issuerKp.address],
    });
    expect(untrustedCheck.valid).toBe(false);
    expect(untrustedCheck.error).toContain('Untrusted issuer');

    // 2. 吊销列表拦截
    const validVc = issueOrganizationCredential(
      {
        agentDid: agentKp.address,
        issuerDid: issuerKp.address,
        organizationName: 'Official Org',
        organizationDomain: 'official.com',
      },
      issuerKp.privateKey
    );

    const revokedCheck = verifyOrganizationCredential(validVc, {
      revocationList: new Set([validVc.id]),
    });
    expect(revokedCheck.valid).toBe(false);
    expect(revokedCheck.error).toContain('revoked');
  });

  it('embeds verifiable credential in AgentCard and signs properly', () => {
    const issuerKp = generateKeyPair();
    const agentKp = generateKeyPair();

    const vc = issueOrganizationCredential(
      {
        agentDid: agentKp.address,
        issuerDid: issuerKp.address,
        organizationName: 'Enterprise Partner Group',
        organizationDomain: 'partner.org',
        badge: 'blue_v',
      },
      issuerKp.privateKey
    );

    const rawCard = createAgentCard({
      did: agentKp.address,
      name: 'Verified Partner Agent',
      description: 'Endorsed by Enterprise Partner Group',
      credentials: [vc],
    });

    const signedCard = signAgentCard(rawCard, agentKp);
    expect(signedCard.credentials).toBeDefined();
    expect(signedCard.credentials?.length).toBe(1);
    expect(signedCard.proof?.signatureValue).toBeDefined();
  });
});
