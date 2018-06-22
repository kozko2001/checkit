const CTX = require('./milagro-crypto-js');

const curve = 'BN254';
const ctx = new CTX(curve);
const hash = new ctx.HASH256();
const rng = new ctx.RAND();

// TODO: this is not random...
rng.clean();
let i;
let RAW = [];
for (i = 0; i < 100; i++) {
    RAW[i] = i;
}

rng.seed(100, RAW);

export const setup = () => {
  // Set generator of G1
  const G1 = new ctx.ECP(0);
  const x = new ctx.BIG(0);
  const y = new ctx.BIG(0);

  x.rcopy(ctx.ROM_CURVE.CURVE_Gx);
  y.rcopy(ctx.ROM_CURVE.CURVE_Gy);
  G1.setxy(x, y);

  // Set generator of G2
  const G2 = new ctx.ECP2(0);
  const qx = new ctx.FP2(0);
  const qy = new ctx.FP2(0);
  x.rcopy(ctx.ROM_CURVE.CURVE_Pxa);
  y.rcopy(ctx.ROM_CURVE.CURVE_Pxb);
  qx.bset(x, y);
  x.rcopy(ctx.ROM_CURVE.CURVE_Pya);
  y.rcopy(ctx.ROM_CURVE.CURVE_Pyb);
  qy.bset(x, y);
  G2.setxy(qx, qy);

  // Set order of G
  const order = new ctx.BIG(0);
  order.rcopy(ctx.ROM_CURVE.CURVE_Order);

  // h1
  const h1 = G1.mul(new ctx.BIG(732489));

  return {
    G1,
    G2,
    order,
    ctx,
    h1,
  };
};

const AUTHORITY_KEY = {
  x: new ctx.BIG(42),
  y: new ctx.BIG(314),
};

export const keygen = () => {
  const { G2 } = setup();

  const pub2x = G2.mul(AUTHORITY_KEY.x);
  const pub2y = G2.mul(AUTHORITY_KEY.y);

  return {
    private: AUTHORITY_KEY,
    public: {
      G2,
      x: pub2x,
      y: pub2y,
    },
  };
};

const stringToBytes = (s) => {
  var b = [];
  for (var i = 0; i < s.length; i++)
    b.push(s.charCodeAt(i));
  return b;
}

// From a string, calculates the hash => is a BigNumber
const hashString = (m) => {
  const bytes = stringToBytes(m);
  hash.process_array(bytes);
  return ctx.BIG.fromBytes(hash.hash());
}

const cloneECP = (p) => {
  const clonedP = new ctx.ECP(0);
  clonedP.copy(p)

  return clonedP;
}


// d = Elgammal secret key (from the user PoV)
// m = message to encrypt
export const prepareBlindSign = (m, d) => {
  const { G1, h1, order } = setup();

  // Generates public key
  const gamma = G1.mul(d);

  // Create commitment cm = g1^m + h1^ro (being ro a random num)
  const mHashed = hashString(m);
  const ro = ctx.BIG.randomnum(order, rng);
  const h1_ro = h1.mul(ro);

  let commitment = G1.mul(mHashed);
  commitment.add(h1_ro);

  // Hash the commitment
  const hNum = hashString(commitment.toString())
  const h = G1.mul(hNum);

  // Create elgammal encryption (G1*k, gamma*k + h*m)
  const k = ctx.BIG.randomnum(order, rng);
  const gamma_k = cloneECP(gamma).mul(k)
  const h_m = h.mul(mHashed)

  const elgammal = [G1.mul(k), gamma_k.add(h_m)]

}
