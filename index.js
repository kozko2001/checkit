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
    private: {
      x,
      y,
    },
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

export const blindSign = (params, privateKeyAuth, cm, a, b, publicKeyUser, proof) => {
  const { G1, order } = params;
  const { x, y } = privateKeyAuth;

  // compute h
  const h = hashToPoint(G1, cm.toString(), order);

  const t2 = a.mul(y);
  const t3 = h.mul(x);
  const t3_2 = b.mul(y);
  t3.add(t3_2);

  return {
    h,
    t2,
    t3,
  };
};

export const unblindSign = (params, sigmaTilde, privateKeyUser) => {
  const { h, t2, t3 } = sigmaTilde;
  const sigma = elgamalDec(params, privateKeyUser, t2, t3);
  return {
    h,
    sigma,
  };
};


export const randomize = (params, sign) => {
  const { order } = params;
  const { h, sigma } = sign;
  const r = randomNumber(order, rng);

  return {
    h: h.mul(r),
    sigma: sigma.mul(r),
  };
};

export const show_blind_sign = (params, vk, sigma, m) => {
  const { order } = params;
  const { G2, x: alpha, y: beta } = vk;
  const { h } = sigma;

  const t = randomNumber(order, rng);

  const kappa = G2.mul(t);
  const kappa_1 = beta.mul(m);

  kappa.add(alpha);
  kappa.add(kappa_1);

  const nu = h.mul(t);

  return {
    kappa,
    nu,
    pi_v: make_pi_v(params, vk, sigma, m, t),
  };
};

export const make_pi_v = (params, vk, sigma, m, t) => {
  const { order, G1, h1 } = params;
  const { G2, x: alpha, y: beta } = vk;
  const { h } = sigma;

  const wm = randomNumber(order, rng);
  const wt = randomNumber(order, rng);

  const Aw = G2.mul(wt);
  const Aw_1 = beta.mul(wm);
  Aw.add(alpha);
  Aw.add(Aw_1);

  const Bw = h.mul(wt);

  const c = to_challange([G1, G2, alpha, Aw, Bw, h1, beta], order);

  const rm = wm;
  let wm_1 = ctx.BIG.modmul(m, c, order);
  wm_1 = ctx.BIG.modneg(wm_1, order);
  wm_1.norm();
  rm.add(wm_1);
  rm.mod(order);
  rm.norm();

  const rt = wt;
  let wt_1 = ctx.BIG.modmul(t, c, order);
  wt_1 = ctx.BIG.modneg(wt_1, order);
  wt_1.norm();
  rt.add(wt_1);
  rt.mod(order);
  rt.norm();

  return {
    rm,
    rt,
    c,
  };
};

export const blind_verify = (params, vk, sign_sigma, kappa, nu, pi_v) => {
  const { h, sigma } = sign_sigma;
  const { G2 } = params;
  const verified = verify_pi_v(params, vk, sign_sigma, kappa, nu, pi_v);
  
  if (!verified) {
    return false;
  }

  // e(h, kappa)
  let z1 = ctx.PAIR.ate(kappa, h);
  z1 = ctx.PAIR.fexp(z1);

  // e(s+nu, g2)
  nu.add(sigma);
  nu.affine(); // no idea what it does but seen on the test file

  let z2 = ctx.PAIR.ate(G2, nu);
  z2 = ctx.PAIR.fexp(z2);

  return z2.equals(z1);
}

export const verify_pi_v = (params, vk, sigma, kappa, nu, pi_v) => {
  const { order, G1, h1 } = params;
  const { G2, x: alpha, y: beta } = vk;
  const { c, rm, rt } = pi_v;
  const { h } = sigma;

  const Aw = kappa.mul(c);
  const Aw2 = G2.mul(rt);
  const Aw3 = beta.mul(rm);

  const negc = ctx.BIG.modneg(c, order);
  const one = new ctx.BIG(1);
  negc.add(one);
  const Aw4 = alpha.mul(negc);

  Aw.add(Aw2);
  Aw.add(Aw3);
  Aw.add(Aw4);

  const Bw = nu.mul(c);
  const Bw2 = h.mul(rt);
  Bw.add(Bw2);

  const calc_c = to_challange([G1, G2, alpha, Aw, Bw, h1, beta], order);
  return ctx.BIG.comp(calc_c, c) === 0;
}
