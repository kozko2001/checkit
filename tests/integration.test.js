import { setup, keygen, prepareBlindSign, elgamalKeygen, hashString, blindSign, unblindSign, randomize, show_blind_sign, blind_verify } from '..';

describe('integration test...', () => {

  it('full path with everything correct', () => {
    const params = setup();
    const m = hashString('age=32', params.order);

    const { private: d, public: gamma } = elgamalKeygen(params);
    const { private: sk, public: vk } = keygen();

    // (user) prepare blindsign
    const { cm, a, b, proof } = prepareBlindSign(params, gamma, m);

    // (verifier) bind sign
    const sigma_tilde = blindSign(params, sk, cm, a, b, gamma, proof);

    // (user) unblind
    let sigma = unblindSign(params, sigma_tilde, d);

    // (user) randomize
    sigma = randomize(params, sigma);

    const { kappa, nu, pi_v } = show_blind_sign(params, vk, sigma, m);

    const verified = blind_verify(params, vk, sigma, kappa, nu, pi_v);

    expect(verified).toStrictEqual(true);
  });

  it('create a credential with some fake-auth, and verify with the real one', () => {
    const params = setup();
    const { ctx } = params;

    const m = hashString('age=32', params.order);

    const { private: d, public: gamma } = elgamalKeygen(params);

    const FAKE_AUTHORITY_KEY = {
      x: new ctx.BIG(1),
      y: new ctx.BIG(2),
    };

    const REAL_AUTHORITY_KEY = {
      x: new ctx.BIG(100),
      y: new ctx.BIG(200),
    };

    // We are creating the credential with the fake authority
    const { private: fake_sk, public: fake_vk } = keygen(FAKE_AUTHORITY_KEY.x, FAKE_AUTHORITY_KEY.y);
    const { private: sk, public: vk } = keygen(REAL_AUTHORITY_KEY.x, REAL_AUTHORITY_KEY.y);

    // (user) prepare blindsign
    const { cm, a, b, proof } = prepareBlindSign(params, gamma, m);

    // (verifier) bind sign
    const sigma_tilde = blindSign(params, fake_sk, cm, a, b, gamma, proof);

    // (user) unblind
    let sigma = unblindSign(params, sigma_tilde, d);

    // (user) randomize
    sigma = randomize(params, sigma);

    // now, we send the credential to an other authority
    const { kappa, nu, pi_v } = show_blind_sign(params, vk, sigma, m);

    const verified = blind_verify(params, vk, sigma, kappa, nu, pi_v);

    expect(verified).toStrictEqual(false);
  });
});
