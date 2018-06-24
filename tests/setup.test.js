import { setup, keygen, prepareBlindSign, elgamalKeygen, elgamalEnc, elgamalDec, hashString, verify_pi_s } from '..';

describe('Setup', () => {
  it('It should have a Generator G1', () => {
    const data = setup();

    const { G1 } = data;

    expect(G1).toHaveProperty('x');
    expect(G1).toHaveProperty('y');
    expect(G1).toHaveProperty('z');
    expect(G1).toHaveProperty('INF', false);
  });

  it('It should have a Generator G2', () => {
    const data = setup();

    const { G2 } = data;

    expect(G2).toHaveProperty('x');
    expect(G2).toHaveProperty('y');
    expect(G2).toHaveProperty('z');
    expect(G2).toHaveProperty('INF', false);
  });

  it('It should have a Order of G', () => {
    const data = setup();

    const { order } = data;
    expect(order).toBeDefined();
    expect(order.nbits()).toBeGreaterThan(32);
  });

  it('Pairing property e(G1 * 2, G2 * 4) === Gtx^8', () => {
    const data = setup();
    const { G1, G2, ctx } = data;

    const Z1 = ctx.PAIR.G1mul(G1, new ctx.BIG(2));
    const Z2 = ctx.PAIR.G2mul(G2, new ctx.BIG(4));

    let z = ctx.PAIR.ate(Z2, Z1);
    z = ctx.PAIR.fexp(z);

    let q = ctx.PAIR.ate(G2, G1);
    q = ctx.PAIR.fexp(q);
    q = ctx.PAIR.GTpow(q, new ctx.BIG(8));

    expect(z).toStrictEqual(q);
  });
});


describe('KeyGen', () => {
  it('Should contain the private keys', () => {
    const keys = keygen();
    expect(keys.private).toHaveProperty('x');
    expect(keys.private).toHaveProperty('y');
  });

  it('Should contain the public keys', () => {
    const keys = keygen();
    expect(keys.public).toHaveProperty('x');
    expect(keys.public).toHaveProperty('y');
  });

  it('public.x = G2 * private.x', () => {
    const keys = keygen();
    const { G2 } = keys.public;

    const calcPubX = G2.mul(keys.private.x);

    expect(calcPubX).toStrictEqual(keys.public.x);
  });

  it('public.y = G2 * private.y', () => {
    const keys = keygen();
    const { G2 } = keys.public;

    const calcPubY = G2.mul(keys.private.y);

    expect(calcPubY).toStrictEqual(keys.public.y);
  });
});

describe('elgamal', () => {
  it('keygen random key', () => {
    const params = setup();
    const keys = elgamalKeygen(params);

    expect(keys).toHaveProperty('private');
    expect(keys).toHaveProperty('public');
  });

  it('keygen specific key', () => {
    const params = setup();
    const { ctx } = params;

    const keys = elgamalKeygen(params, new ctx.BIG(42));

    expect(keys.private.toString()).toStrictEqual('000000000000000000000000000000000000000000000000000000000000002a');
  });

  it('elgamal encryption', () => {
    const params = setup();
    const { G1, ctx } = params;
    const keys = elgamalKeygen(params, new ctx.BIG(42));

    const h = G1.mul(new ctx.BIG(999));
    const m = new ctx.BIG(5);

    const enc = elgamalEnc(params, keys.public, m, h);

    expect(enc).toHaveProperty('a');
    expect(enc).toHaveProperty('b');
    expect(enc).toHaveProperty('k');
  });

  it('elgamal decryption', () => {
    const params = setup();
    const { G1, ctx } = params;
    const keys = elgamalKeygen(params, new ctx.BIG(42));

    const h = G1.mul(new ctx.BIG(999));
    const m = new ctx.BIG(5);

    const enc = elgamalEnc(params, keys.public, m, h);
    const { a, b } = enc;
    const dec = elgamalDec(params, keys.private, a, b);

    const expected = h.mul(m);

    expect(dec.toString()).toStrictEqual(expected.toString());
  });
});

describe('prepareBlindSign', () => {
  let keys;

  beforeEach(() => {
    const params = setup();
    const { ctx } = params;
    keys = elgamalKeygen(params, new ctx.BIG(42));
  });

  it('prepare blind sing contains important attributes', () => {
    const params = setup();

    const m = hashString('age=32', params.order);
    const blindSign = prepareBlindSign(params, keys.public, m);

    expect(blindSign).toHaveProperty('a');
    expect(blindSign).toHaveProperty('b');
    expect(blindSign).toHaveProperty('cm');
    expect(blindSign).toHaveProperty('proof');
  });

  it('verify ZKP of blindSign', () => {
    const params = setup();

    const m = hashString('age=32', params.order);
    const blindSign = prepareBlindSign(params, keys.public, m);
    const {
      proof,
      a,
      b,
      cm,
    } = blindSign;

    const ok = verify_pi_s(params, keys.public, a, b, cm, proof);
    expect(ok).toBe(true);
  });
});
