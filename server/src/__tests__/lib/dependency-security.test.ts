import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const semver = require('semver');
// Exact patched floors, not ignored advisories. The lockfile remains authoritative.
const floors: Record<string, string> = {
  compression: '1.8.2', 'fast-uri': '3.1.8', 'ip-address': '10.7.1',
  'js-yaml': '4.3.2', multer: '2.4.0', 'proxy-addr': '2.0.8', qs: '6.16.0',
  sharp: '0.35.5', 'source-map-js': '1.2.2', undici: '6.28.1',
};

describe('reviewed dependency security regressions (#468)', () => {
  for (const [name, minimum] of Object.entries(floors)) {
    it(`${name} meets the reviewed patched floor`, () => {
      expect(semver.gte((name === 'sharp' ? require('sharp').versions.sharp : require(`${name}/package.json`).version), minimum)).toBe(true);
    });
  }

  it('does not trust unrelated IPv4 through a malformed mapped IPv6 subnet', () => {
    const proxyaddr = require('proxy-addr');
    expect(proxyaddr.compile('::ffff:10.0.0.0/8')('203.0.113.1', 0)).toBe(false);
    expect(proxyaddr.compile('10.0.0.0/8')('10.1.2.3', 0)).toBe(true);
    expect(proxyaddr.compile('10.0.0.0/8')('203.0.113.1', 0)).toBe(false);
  });

  it('canonicalizes percent-encoded host case in scheme-relative references', () => {
    const uri = require('fast-uri');
    expect(uri.parse('//%41.com').host).toBe('a.com');
    expect(uri.equal('//%41.com', '//a.com')).toBe(true);
  });

  it('rejects cross-family subnet matches while preserving valid same-family matches', () => {
    const { Address4, Address6 } = require('ip-address');
    expect(new Address6('a00::1').isInSubnet(new Address4('10.0.0.0/8'))).toBe(false);
    expect(new Address4('32.0.0.1').isInSubnet(new Address6('2000::/3'))).toBe(false);
    expect(new Address4('10.1.2.3').isInSubnet(new Address4('10.0.0.0/8'))).toBe(true);
    expect(new Address6('fe90::1').isLinkLocal()).toBe(true);
  });

  it('bounds malformed IPv6 diagnostics without dangerous allocation probes', () => {
    const { Address6 } = require('ip-address');
    // Small bounded input is enough to exercise the fix; never run the 32 MiB PoC.
    try {
      new Address6('!'.repeat(128));
      throw new Error('accepted invalid input');
    } catch (error) {
      expect((error as Error).name).toBe('AddressError');
      expect((error as { parseMessage?: string }).parseMessage).toBeUndefined();
    }
  });

  it('enforces comma array limits for bracket keys', () => {
    const qs = require('qs');
    expect(() => qs.parse('a[]=1,2,3,4', { comma: true, arrayLimit: 3, throwOnLimitExceeded: true })).toThrow(RangeError);
    expect(qs.parse('a=1,2', { comma: true, arrayLimit: 3 }).a).toEqual(['1', '2']);
  });

  it('counts empty YAML merge sources against the configured budget', () => {
    const yaml = require('js-yaml');
    expect(() => yaml.load('arr: &arr [{}, {}, {}]\ntarget:\n  <<: *arr\n', { maxTotalMergeKeys: 1 })).toThrow();
    expect(yaml.load('answer: 42')).toEqual({ answer: 42 });
  });

  it('loads the patched native image library and can decode a synthetic image', async () => {
    const sharp = require('sharp');
    expect(semver.gte(sharp.versions.sharp, '0.35.5')).toBe(true);
    const png = await sharp({ create: { width: 2, height: 2, channels: 3, background: '#ffffff' } }).png().toBuffer();
    expect((await sharp(png).metadata()).width).toBe(2);
  });
});
