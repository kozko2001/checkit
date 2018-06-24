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

// TODO: Move hash and conversion utils to another file
const stringToBytes = (s) => {
  const b = [];
  for (let i = 0; i < s.length; i += 1) { b.push(s.charCodeAt(i)); }
  return b;
};

// From a string, calculates the hash => is a BigNumber
export const hashString = (m, order) => {
  const bytes = stringToBytes(m);
  hash.process_array(bytes);
  const p = ctx.BIG.fromBytes(hash.hash());
  p.mod(order);
  return p;
};

const cloneECP = (p) => {
  const clonedP = new ctx.ECP(0);
  clonedP.copy(p);

  return clonedP;
};

// hashes a message and then returns a point on the EC G
const hashToPoint = (G, m, order) => {
  const hashBN = hashString(m, order);
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
  const h1 = hashToPoint(G1, 'h0', order);

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

export const prepareBlindSign = (params, gamma, m) => {
  const { G1, h1, order } = params;

  // Create commitment cm = g1^m + h1^ro (being ro a random num)
  const r = randomNumber(order, rng);
  const cm = G1.mul(r);
  cm.add(h1.mul(m));

  // build elgamal encryption
  const h = hashToPoint(G1, cm.toString(), order);
  const enc = elgamalEnc(params, gamma, m, h);

  const proof = make_pi_s(params, gamma, enc.a, enc.b, cm, enc.k, r, m);

  return {
    cm,
    a: enc.a,
    b: enc.b,
    proof,
  };
};

const to_challange = (elements, order) => {
  const p = elements.map(e => e.toString()).join(',');
  return hashString(p, order);
};

export const make_pi_s = (params, gamma, a, b, cm, k, r, m) => {
  const {
    order,
    G1,
    h1,
    G2,
  } = params;

  // create witnesses
  const wr = randomNumber(order, rng);
  const wk = randomNumber(order, rng);
  const wm = randomNumber(order, rng);

  // compute h
  const h = hashToPoint(G1, cm.toString(), order);

  // compute witnesses
  const Aw = G1.mul(wk);

  const Bw = gamma.mul(wk);
  Bw.add(h.mul(wm));

  const Cw = G1.mul(wr);
  Cw.add(h1.mul(wm));

  // create the challange
  const c = to_challange([G1, G2, cm, h, Cw, h1, Aw, Bw], order);

  // create responses
  const rr = wr;
  let wr_1 = ctx.BIG.modmul(r, c, order);
  wr_1 = ctx.BIG.modneg(wr_1, order);
  wr_1.norm();
  rr.add(wr_1);
  rr.mod(order);
  rr.norm();

  const rk = wk;
  let wk_1 = ctx.BIG.modmul(k, c, order);
  wk_1 = ctx.BIG.modneg(wk_1, order);
  wk_1.norm();
  rk.add(wk_1);
  rk.mod(order);
  rk.norm();

  const rm = wm;
  let wm_1 = ctx.BIG.modmul(c, m, order);
  wm_1 = ctx.BIG.modneg(wm_1, order);
  wm_1.norm();
  rm.add(wm_1);
  rm.mod(order);
  rm.norm();

  return {
    c,
    rk,
    rm,
    rr,
  };
};

export const verify_pi_s = (params, gamma, a, b, cm, proof) => {
  const {
    G1,
    G2,
    order,
    h1,
  } = params;

  const {
    c,
    rk,
    rm,
    rr,
  } = proof;
  // compute h
  const h = hashToPoint(G1, cm.toString(), order);

  // recompute witnesses commitments
  const Aw = a.mul(c);

  Aw.add(G1.mul(rk));

  const Bw = b.mul(c);
  Bw.add(gamma.mul(rk));
  Bw.add(h.mul(rm));

  const Cw = cm.mul(c);
  const Cw_1 = G1.mul(rr);
  const Cw_2 = h1.mul(rm);
  Cw.add(Cw_1);
  Cw.add(Cw_2);

  // create the challange
  const calc_c = to_challange([G1, G2, cm, h, Cw, h1, Aw, Bw], order);

  return ctx.BIG.comp(calc_c, c) === 0;
};
