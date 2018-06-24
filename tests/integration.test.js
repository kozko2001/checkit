import { setup, keygen, prepareBlindSign, elgamalKeygen, elgamalEnc, elgamalDec, hashString, verify_pi_s, blindSign, unblindSign, randomize, show_blind_sign } from '..';

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

    // const verified = blind_verify(params, vk, sigma, kappa, nu, pi_v);
  });
});
