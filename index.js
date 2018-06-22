const CTX = require('./milagro-crypto-js');

const curve = 'BN254';
const ctx = new CTX(curve);
const hash = new ctx.HASH256();
const rng = new ctx.RAND();

// TODO: this is not random...
rng.clean();
const RAW = [];
for (let i = 0; i < 100; i += 1) {
  RAW[i] = i;
}

rng.seed(100, RAW);

/// TODO: Move hash and conversion utils to another file
const stringToBytes = (s) => {
  const b = [];
  for (let i = 0; i < s.length; i += 1) { b.push(s.charCodeAt(i)); }
  return b;
};

// From a string, calculates the hash => is a BigNumber
const hashString = (m) => {
  const bytes = stringToBytes(m);
  hash.process_array(bytes);
  return ctx.BIG.fromBytes(hash.hash());
};

const cloneECP = (p) => {
  const clonedP = new ctx.ECP(0);
  clonedP.copy(p);

  return clonedP;
};

// hashes a message and then returns a point on the EC G
const hashToPoint = (G, m) => {
  const hashBN = hashString(m);
  return G.mul(hashBN);
};

// Get a random number between 0 and BN
const randomNumber = (Bn, _rng) => ctx.BIG.randomnum(Bn, _rng);

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
  const h1 = hashToPoint(G1, 'h0');

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

export const keygen = (x = AUTHORITY_KEY.x, y = AUTHORITY_KEY.y) => {
  const { G2 } = setup();

  const pub2x = G2.mul(x);
  const pub2y = G2.mul(y);

  return {
    private: AUTHORITY_KEY,
    public: {
      G2,
      x: pub2x,
      y: pub2y,
    },
  };
};

export const elgamalKeygen = (params, privKey) => {
  const { order, G1 } = params;

  let d = privKey;
  if (!d) {
    d = randomNumber(order, rng);
  }

  const gamma = G1.mul(d);

  return {
    private: d,
    public: gamma,
  };
};

export const elgamalEnc = (params, gamma, m, h) => {
  const { order, G1 } = params;

  const k = randomNumber(order, rng);
  const a = G1.mul(k);
  const b = gamma.mul(k);
  b.add(h.mul(m));

  return {
    a,
    b,
    k,
  };
};


export const elgamalDec = (params, priv, a, b) => {
  const x = a.mul(priv);
  x.neg();

  const y = cloneECP(b);
  y.add(x);

  return y;
};

// d = Elgammal secret key (from the user PoV)
// m = message to encrypt
export const prepareBlindSign = (params, d, m) => {
  const { G1, h1, order } = params;

  // Generates public key
  const gamma = G1.mul(d);

  // Create commitment cm = g1^m + h1^ro (being ro a random num)
  const g1_m = hashToPoint(G1, m);
  const ro = ctx.BIG.randomnum(order, rng);
  const h1_ro = h1.mul(ro);

  g1_m.add(h1_ro);
  const commitment = g1_m;

  // Hash the commitment
  const h = hashToPoint(G1, commitment.toString());
};
