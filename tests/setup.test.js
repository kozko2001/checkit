import { setup } from '..';

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
