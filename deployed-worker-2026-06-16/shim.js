var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// build/index.js
import { WorkerEntrypoint as mt } from "cloudflare:workers";
import K from "./de07d22cc80917c7338ba4d9711d7402b19fc578-index_bg.wasm";
var $ = globalThis.__worker_init_state = { criticalError: false, instanceId: 0 };
var S = class {
  static {
    __name(this, "S");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, ft.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), s.__wbg_containerstartupoptions_free(t, 0);
  }
  get enableInternet() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = s.__wbg_get_containerstartupoptions_enableInternet(this.__wbg_ptr), t === 16777215 ? void 0 : t !== 0;
  }
  get entrypoint() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let i = s.__wbindgen_add_to_stack_pointer(-16);
      c(), s.__wbg_get_containerstartupoptions_entrypoint(i, this.__wbg_ptr);
      var t = b().getInt32(i + 0, true), e = b().getInt32(i + 4, true), n = lt(t, e).slice();
      return s.__wbindgen_export4(t, e * 4, 4), n;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get env() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = s.__wbg_get_containerstartupoptions_env(this.__wbg_ptr), l(t);
  }
  set enableInternet(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_containerstartupoptions_enableInternet(this.__wbg_ptr, g(t) ? 16777215 : t ? 1 : 0);
  }
  set entrypoint(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e = pt(t, s.__wbindgen_export), n = p;
    c(), s.__wbg_set_containerstartupoptions_entrypoint(this.__wbg_ptr, e, n);
  }
  set env(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_containerstartupoptions_env(this.__wbg_ptr, o(t));
  }
};
Symbol.dispose && (S.prototype[Symbol.dispose] = S.prototype.free);
var k = class {
  static {
    __name(this, "k");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, at.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), s.__wbg_intounderlyingbytesource_free(t, 0);
  }
  get autoAllocateChunkSize() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = s.intounderlyingbytesource_autoAllocateChunkSize(this.__wbg_ptr), t >>> 0;
  }
  cancel() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw();
    c(), s.intounderlyingbytesource_cancel(t);
  }
  pull(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = s.intounderlyingbytesource_pull(this.__wbg_ptr, o(t)), l(e);
  }
  start(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.intounderlyingbytesource_start(this.__wbg_ptr, o(t));
  }
  get type() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = s.intounderlyingbytesource_type(this.__wbg_ptr), st[t];
  }
};
Symbol.dispose && (k.prototype[Symbol.dispose] = k.prototype.free);
var W = class {
  static {
    __name(this, "W");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, bt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), s.__wbg_intounderlyingsink_free(t, 0);
  }
  abort(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e = this.__destroy_into_raw(), n;
    return c(), n = s.intounderlyingsink_abort(e, o(t)), l(n);
  }
  close() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw(), e;
    return c(), e = s.intounderlyingsink_close(t), l(e);
  }
  write(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = s.intounderlyingsink_write(this.__wbg_ptr, o(t)), l(e);
  }
};
Symbol.dispose && (W.prototype[Symbol.dispose] = W.prototype.free);
var A = class {
  static {
    __name(this, "A");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, dt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), s.__wbg_intounderlyingsource_free(t, 0);
  }
  cancel() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t = this.__destroy_into_raw();
    c(), s.intounderlyingsource_cancel(t);
  }
  pull(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let e;
    return c(), e = s.intounderlyingsource_pull(this.__wbg_ptr, o(t)), l(e);
  }
};
Symbol.dispose && (A.prototype[Symbol.dispose] = A.prototype.free);
var E = class _ {
  static {
    __name(this, "_");
  }
  static __wrap(t) {
    let e = Object.create(_.prototype);
    return e.__wbg_ptr = t, Object.defineProperty(e, "__wbg_inst", { value: u, writable: true }), H.register(e, { ptr: t, instance: u }, e), e;
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, H.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), s.__wbg_minifyconfig_free(t, 0);
  }
  get css() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = s.__wbg_get_minifyconfig_css(this.__wbg_ptr), t !== 0;
  }
  get html() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = s.__wbg_get_minifyconfig_html(this.__wbg_ptr), t !== 0;
  }
  get js() {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    let t;
    return c(), t = s.__wbg_get_minifyconfig_js(this.__wbg_ptr), t !== 0;
  }
  set css(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_minifyconfig_css(this.__wbg_ptr, t);
  }
  set html(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_minifyconfig_html(this.__wbg_ptr, t);
  }
  set js(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_minifyconfig_js(this.__wbg_ptr, t);
  }
};
Symbol.dispose && (E.prototype[Symbol.dispose] = E.prototype.free);
var O = class {
  static {
    __name(this, "O");
  }
  __destroy_into_raw() {
    let t = this.__wbg_ptr;
    return this.__wbg_ptr = 0, gt.unregister(this), t;
  }
  free() {
    let t = this.__destroy_into_raw();
    c(), s.__wbg_r2range_free(t, 0);
  }
  get length() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let n = s.__wbindgen_add_to_stack_pointer(-16);
      c(), s.__wbg_get_r2range_length(n, this.__wbg_ptr);
      var t = b().getInt32(n + 0, true), e = b().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get offset() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let n = s.__wbindgen_add_to_stack_pointer(-16);
      c(), s.__wbg_get_r2range_offset(n, this.__wbg_ptr);
      var t = b().getInt32(n + 0, true), e = b().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  get suffix() {
    try {
      if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
      let n = s.__wbindgen_add_to_stack_pointer(-16);
      c(), s.__wbg_get_r2range_suffix(n, this.__wbg_ptr);
      var t = b().getInt32(n + 0, true), e = b().getFloat64(n + 8, true);
      return t === 0 ? void 0 : e;
    } finally {
      s.__wbindgen_add_to_stack_pointer(16);
    }
  }
  set length(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_r2range_length(this.__wbg_ptr, !g(t), g(t) ? 0 : t);
  }
  set offset(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_r2range_offset(this.__wbg_ptr, !g(t), g(t) ? 0 : t);
  }
  set suffix(t) {
    if (this.__wbg_inst !== void 0 && this.__wbg_inst !== u) throw new Error("Invalid stale object from previous Wasm instance");
    c(), s.__wbg_set_r2range_suffix(this.__wbg_ptr, !g(t), g(t) ? 0 : t);
  }
};
Symbol.dispose && (O.prototype[Symbol.dispose] = O.prototype.free);
function D() {
  u++, v = null, z = null, typeof numBytesDecoded < "u" && (numBytesDecoded = 0), typeof p < "u" && (p = 0), typeof h < "u" && (h = new Array(1024).fill(void 0), h = h.concat([void 0, null, true, false]), typeof R < "u" && (R = h.length)), nt = false, B = new WebAssembly.Instance(K, et()), s = B.exports, s.__wbindgen_start();
}
__name(D, "D");
function Q() {
  let _2;
  return c(), _2 = s.__worker_init_state(), l(_2);
}
__name(Q, "Q");
function X(_2, t, e) {
  let n;
  return c(), n = s.fetch(o(_2), o(t), o(e)), l(n);
}
__name(X, "X");
function Y() {
  c(), s.init();
}
__name(Y, "Y");
function Z(_2, t, e) {
  let n;
  return c(), n = s.scheduled(o(_2), o(t), o(e)), l(n);
}
__name(Z, "Z");
function tt() {
  c(), s.start();
}
__name(tt, "tt");
function et() {
  return { __proto__: null, "./index_bg.js": { __proto__: null, __wbg_Error_bce6d499ff0a4aff: /* @__PURE__ */ __name(function(t, e) {
    let n = Error(y(t, e));
    return o(n);
  }, "__wbg_Error_bce6d499ff0a4aff"), __wbg_Number_b7972a139bfbfdf0: /* @__PURE__ */ __name(function(t) {
    return Number(r(t));
  }, "__wbg_Number_b7972a139bfbfdf0"), __wbg_String_8564e559799eccda: /* @__PURE__ */ __name(function(t, e) {
    let n = String(r(e)), i = x(n, s.__wbindgen_export, s.__wbindgen_export2), f = p;
    b().setInt32(t + 4, f, true), b().setInt32(t + 0, i, true);
  }, "__wbg_String_8564e559799eccda"), __wbg___wbindgen_bigint_get_as_i64_410e28c7b761ad83: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e), i = typeof n == "bigint" ? n : void 0;
    b().setBigInt64(t + 8, g(i) ? BigInt(0) : i, true), b().setInt32(t + 0, !g(i), true);
  }, "__wbg___wbindgen_bigint_get_as_i64_410e28c7b761ad83"), __wbg___wbindgen_boolean_get_2304fb8c853028c8: /* @__PURE__ */ __name(function(t) {
    let e = r(t), n = typeof e == "boolean" ? e : void 0;
    return g(n) ? 16777215 : n ? 1 : 0;
  }, "__wbg___wbindgen_boolean_get_2304fb8c853028c8"), __wbg___wbindgen_debug_string_edece8177ad01481: /* @__PURE__ */ __name(function(t, e) {
    let n = L(r(e)), i = x(n, s.__wbindgen_export, s.__wbindgen_export2), f = p;
    b().setInt32(t + 4, f, true), b().setInt32(t + 0, i, true);
  }, "__wbg___wbindgen_debug_string_edece8177ad01481"), __wbg___wbindgen_in_07056af4f902c445: /* @__PURE__ */ __name(function(t, e) {
    return r(t) in r(e);
  }, "__wbg___wbindgen_in_07056af4f902c445"), __wbg___wbindgen_is_bigint_aeae3893f30ed54e: /* @__PURE__ */ __name(function(t) {
    return typeof r(t) == "bigint";
  }, "__wbg___wbindgen_is_bigint_aeae3893f30ed54e"), __wbg___wbindgen_is_function_5cd60d5cf78b4eef: /* @__PURE__ */ __name(function(t) {
    return typeof r(t) == "function";
  }, "__wbg___wbindgen_is_function_5cd60d5cf78b4eef"), __wbg___wbindgen_is_null_or_undefined_74c58242e8529df3: /* @__PURE__ */ __name(function(t) {
    return r(t) == null;
  }, "__wbg___wbindgen_is_null_or_undefined_74c58242e8529df3"), __wbg___wbindgen_is_object_b4593df85baada48: /* @__PURE__ */ __name(function(t) {
    let e = r(t);
    return typeof e == "object" && e !== null;
  }, "__wbg___wbindgen_is_object_b4593df85baada48"), __wbg___wbindgen_is_string_dde0fd9020db4434: /* @__PURE__ */ __name(function(t) {
    return typeof r(t) == "string";
  }, "__wbg___wbindgen_is_string_dde0fd9020db4434"), __wbg___wbindgen_is_undefined_35bb9f4c7fd651d5: /* @__PURE__ */ __name(function(t) {
    return r(t) === void 0;
  }, "__wbg___wbindgen_is_undefined_35bb9f4c7fd651d5"), __wbg___wbindgen_jsval_eq_c0ed08b3e0f393b9: /* @__PURE__ */ __name(function(t, e) {
    return r(t) === r(e);
  }, "__wbg___wbindgen_jsval_eq_c0ed08b3e0f393b9"), __wbg___wbindgen_jsval_loose_eq_0ad77b7717db155c: /* @__PURE__ */ __name(function(t, e) {
    return r(t) == r(e);
  }, "__wbg___wbindgen_jsval_loose_eq_0ad77b7717db155c"), __wbg___wbindgen_number_get_f73a1244370fcc2c: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e), i = typeof n == "number" ? n : void 0;
    b().setFloat64(t + 8, g(i) ? 0 : i, true), b().setInt32(t + 0, !g(i), true);
  }, "__wbg___wbindgen_number_get_f73a1244370fcc2c"), __wbg___wbindgen_string_get_d109740c0d18f4d7: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e), i = typeof n == "string" ? n : void 0;
    var f = g(i) ? 0 : x(i, s.__wbindgen_export, s.__wbindgen_export2), d = p;
    b().setInt32(t + 4, d, true), b().setInt32(t + 0, f, true);
  }, "__wbg___wbindgen_string_get_d109740c0d18f4d7"), __wbg___wbindgen_throw_9c31b086c2b26051: /* @__PURE__ */ __name(function(t, e) {
    throw new Error(y(t, e));
  }, "__wbg___wbindgen_throw_9c31b086c2b26051"), __wbg__wbg_cb_unref_3fa391f3fcdb55f8: /* @__PURE__ */ __name(function(t) {
    r(t)._wbg_cb_unref();
  }, "__wbg__wbg_cb_unref_3fa391f3fcdb55f8"), __wbg_all_5a0f50ed86bbeec0: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).all();
      return o(e);
    }, arguments);
  }, "__wbg_all_5a0f50ed86bbeec0"), __wbg_bind_047aba25eb382b5a: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = r(t).bind(...l(e));
      return o(n);
    }, arguments);
  }, "__wbg_bind_047aba25eb382b5a"), __wbg_body_acbb5ec9cd18657f: /* @__PURE__ */ __name(function(t) {
    let e = r(t).body;
    return g(e) ? 0 : o(e);
  }, "__wbg_body_acbb5ec9cd18657f"), __wbg_buffer_8d6798e32d1afd34: /* @__PURE__ */ __name(function(t) {
    let e = r(t).buffer;
    return o(e);
  }, "__wbg_buffer_8d6798e32d1afd34"), __wbg_byobRequest_9d8c3b7b2f692560: /* @__PURE__ */ __name(function(t) {
    let e = r(t).byobRequest;
    return g(e) ? 0 : o(e);
  }, "__wbg_byobRequest_9d8c3b7b2f692560"), __wbg_byteLength_c0cecdd68fab1693: /* @__PURE__ */ __name(function(t) {
    return r(t).byteLength;
  }, "__wbg_byteLength_c0cecdd68fab1693"), __wbg_byteOffset_3791b0030cc3b490: /* @__PURE__ */ __name(function(t) {
    return r(t).byteOffset;
  }, "__wbg_byteOffset_3791b0030cc3b490"), __wbg_call_13665d9f14390edc: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = r(t).call(r(e));
      return o(n);
    }, arguments);
  }, "__wbg_call_13665d9f14390edc"), __wbg_call_dfde26266607c996: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n) {
      let i = r(t).call(r(e), r(n));
      return o(i);
    }, arguments);
  }, "__wbg_call_dfde26266607c996"), __wbg_cancel_bee68d5707c614fb: /* @__PURE__ */ __name(function(t) {
    let e = r(t).cancel();
    return o(e);
  }, "__wbg_cancel_bee68d5707c614fb"), __wbg_catch_ec5061a695c26496: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t).catch(r(e));
    return o(n);
  }, "__wbg_catch_ec5061a695c26496"), __wbg_cause_af1d0ccfb7354a29: /* @__PURE__ */ __name(function(t) {
    let e = r(t).cause;
    return o(e);
  }, "__wbg_cause_af1d0ccfb7354a29"), __wbg_cf_19e06ec190adc114: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).cf;
      return g(e) ? 0 : o(e);
    }, arguments);
  }, "__wbg_cf_19e06ec190adc114"), __wbg_cf_99dfada43d8986a1: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).cf;
      return g(e) ? 0 : o(e);
    }, arguments);
  }, "__wbg_cf_99dfada43d8986a1"), __wbg_close_53179a3d37ed525d: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      r(t).close();
    }, arguments);
  }, "__wbg_close_53179a3d37ed525d"), __wbg_close_807d553ef8405788: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      r(t).close();
    }, arguments);
  }, "__wbg_close_807d553ef8405788"), __wbg_constructor_9a9e391694baf7d0: /* @__PURE__ */ __name(function(t) {
    let e = r(t).constructor;
    return o(e);
  }, "__wbg_constructor_9a9e391694baf7d0"), __wbg_cron_4572e7e7bfe66d10: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = r(e).cron, i = x(n, s.__wbindgen_export, s.__wbindgen_export2), f = p;
      b().setInt32(t + 4, f, true), b().setInt32(t + 0, i, true);
    }, arguments);
  }, "__wbg_cron_4572e7e7bfe66d10"), __wbg_crypto_38df2bab126b63dc: /* @__PURE__ */ __name(function(t) {
    let e = r(t).crypto;
    return o(e);
  }, "__wbg_crypto_38df2bab126b63dc"), __wbg_done_54b8da57023b7ed2: /* @__PURE__ */ __name(function(t) {
    return r(t).done;
  }, "__wbg_done_54b8da57023b7ed2"), __wbg_enqueue_c3ce0a986a355a8c: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      r(t).enqueue(r(e));
    }, arguments);
  }, "__wbg_enqueue_c3ce0a986a355a8c"), __wbg_entries_564a7e8b1e54ede5: /* @__PURE__ */ __name(function(t) {
    let e = Object.entries(r(t));
    return o(e);
  }, "__wbg_entries_564a7e8b1e54ede5"), __wbg_error_19d45ba06d627441: /* @__PURE__ */ __name(function(t, e) {
    console.error(r(t), r(e));
  }, "__wbg_error_19d45ba06d627441"), __wbg_error_a6fa202b58aa1cd3: /* @__PURE__ */ __name(function(t, e) {
    let n, i;
    try {
      n = t, i = e, console.error(y(t, e));
    } finally {
      c(), s.__wbindgen_export4(n, i, 1);
    }
  }, "__wbg_error_a6fa202b58aa1cd3"), __wbg_error_f085d7e62279b703: /* @__PURE__ */ __name(function(t) {
    console.error(r(t));
  }, "__wbg_error_f085d7e62279b703"), __wbg_fetch_d191ad743cc4be04: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = r(t).fetch(r(e));
      return o(n);
    }, arguments);
  }, "__wbg_fetch_d191ad743cc4be04"), __wbg_first_97b69bd0708feb7b: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n) {
      let i = r(t).first(e === 0 ? void 0 : y(e, n));
      return o(i);
    }, arguments);
  }, "__wbg_first_97b69bd0708feb7b"), __wbg_getRandomValues_c44a50d8cfdaebeb: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      r(t).getRandomValues(r(e));
    }, arguments);
  }, "__wbg_getRandomValues_c44a50d8cfdaebeb"), __wbg_getReader_9facd4f899beac89: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).getReader();
      return o(e);
    }, arguments);
  }, "__wbg_getReader_9facd4f899beac89"), __wbg_getTime_09f1dd40a44edb30: /* @__PURE__ */ __name(function(t) {
    return r(t).getTime();
  }, "__wbg_getTime_09f1dd40a44edb30"), __wbg_get_0b3f3bb74d16b7ad: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n, i) {
      let f = r(e).get(y(n, i));
      var d = g(f) ? 0 : x(f, s.__wbindgen_export, s.__wbindgen_export2), w = p;
      b().setInt32(t + 4, w, true), b().setInt32(t + 0, d, true);
    }, arguments);
  }, "__wbg_get_0b3f3bb74d16b7ad"), __wbg_get_3e9a707ab7d352eb: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = Reflect.get(r(t), r(e));
      return o(n);
    }, arguments);
  }, "__wbg_get_3e9a707ab7d352eb"), __wbg_get_98fdf51d029a75eb: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t)[e >>> 0];
    return o(n);
  }, "__wbg_get_98fdf51d029a75eb"), __wbg_get_dcf82ab8aad1a593: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = Reflect.get(r(t), r(e));
      return o(n);
    }, arguments);
  }, "__wbg_get_dcf82ab8aad1a593"), __wbg_get_done_06210bfbda89c407: /* @__PURE__ */ __name(function(t) {
    let e = r(t).done;
    return g(e) ? 16777215 : e ? 1 : 0;
  }, "__wbg_get_done_06210bfbda89c407"), __wbg_get_f591d97c88ae94ef: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = Reflect.get(r(t), r(e));
      return g(n) ? 0 : o(n);
    }, arguments);
  }, "__wbg_get_f591d97c88ae94ef"), __wbg_get_unchecked_1dfe6d05ad91d9b7: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t)[e >>> 0];
    return o(n);
  }, "__wbg_get_unchecked_1dfe6d05ad91d9b7"), __wbg_get_value_31eb9abef97d98cb: /* @__PURE__ */ __name(function(t) {
    let e = r(t).value;
    return o(e);
  }, "__wbg_get_value_31eb9abef97d98cb"), __wbg_get_with_ref_key_6412cf3094599694: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t)[r(e)];
    return o(n);
  }, "__wbg_get_with_ref_key_6412cf3094599694"), __wbg_headers_18f39f24d3837dc1: /* @__PURE__ */ __name(function(t) {
    let e = r(t).headers;
    return o(e);
  }, "__wbg_headers_18f39f24d3837dc1"), __wbg_headers_4cfb0c75793d7a8d: /* @__PURE__ */ __name(function(t) {
    let e = r(t).headers;
    return o(e);
  }, "__wbg_headers_4cfb0c75793d7a8d"), __wbg_instanceId_d6c260a59e274d0b: /* @__PURE__ */ __name(function(t) {
    return r(t).instanceId;
  }, "__wbg_instanceId_d6c260a59e274d0b"), __wbg_instanceof_ArrayBuffer_53db37b06f6b9afe: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof ArrayBuffer;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_ArrayBuffer_53db37b06f6b9afe"), __wbg_instanceof_Error_b3f7e146d654031a: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Error;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Error_b3f7e146d654031a"), __wbg_instanceof_Map_16f217b9a2a08d8c: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Map;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Map_16f217b9a2a08d8c"), __wbg_instanceof_ReadableStream_9a3d74fc91aa9c55: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof ReadableStream;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_ReadableStream_9a3d74fc91aa9c55"), __wbg_instanceof_Response_ecfc823e8fb354e2: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Response;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Response_ecfc823e8fb354e2"), __wbg_instanceof_Uint8Array_abd07d4bd221d50b: /* @__PURE__ */ __name(function(t) {
    let e;
    try {
      e = r(t) instanceof Uint8Array;
    } catch {
      e = false;
    }
    return e;
  }, "__wbg_instanceof_Uint8Array_abd07d4bd221d50b"), __wbg_isArray_94898ed3aad6947b: /* @__PURE__ */ __name(function(t) {
    return Array.isArray(r(t));
  }, "__wbg_isArray_94898ed3aad6947b"), __wbg_isSafeInteger_01e964d144ad3a55: /* @__PURE__ */ __name(function(t) {
    return Number.isSafeInteger(r(t));
  }, "__wbg_isSafeInteger_01e964d144ad3a55"), __wbg_iterator_1441b47f341dc34f: /* @__PURE__ */ __name(function() {
    return o(Symbol.iterator);
  }, "__wbg_iterator_1441b47f341dc34f"), __wbg_keys_610666c87d9e3542: /* @__PURE__ */ __name(function(t) {
    let e = r(t).keys();
    return o(e);
  }, "__wbg_keys_610666c87d9e3542"), __wbg_length_2591a0f4f659a55c: /* @__PURE__ */ __name(function(t) {
    return r(t).length;
  }, "__wbg_length_2591a0f4f659a55c"), __wbg_length_56fcd3e2b7e0299d: /* @__PURE__ */ __name(function(t) {
    return r(t).length;
  }, "__wbg_length_56fcd3e2b7e0299d"), __wbg_log_eb752234eec406d1: /* @__PURE__ */ __name(function(t) {
    console.log(r(t));
  }, "__wbg_log_eb752234eec406d1"), __wbg_message_324ac511aeaf710e: /* @__PURE__ */ __name(function(t) {
    let e = r(t).message;
    return o(e);
  }, "__wbg_message_324ac511aeaf710e"), __wbg_method_eadeb6c481ed3b2d: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e).method, i = x(n, s.__wbindgen_export, s.__wbindgen_export2), f = p;
    b().setInt32(t + 4, f, true), b().setInt32(t + 0, i, true);
  }, "__wbg_method_eadeb6c481ed3b2d"), __wbg_minifyconfig_new: /* @__PURE__ */ __name(function(t) {
    let e = E.__wrap(t);
    return o(e);
  }, "__wbg_minifyconfig_new"), __wbg_msCrypto_bd5a034af96bcba6: /* @__PURE__ */ __name(function(t) {
    let e = r(t).msCrypto;
    return o(e);
  }, "__wbg_msCrypto_bd5a034af96bcba6"), __wbg_name_7eee4ed497d7c416: /* @__PURE__ */ __name(function(t) {
    let e = r(t).name;
    return o(e);
  }, "__wbg_name_7eee4ed497d7c416"), __wbg_name_d09e9b472d8320d3: /* @__PURE__ */ __name(function(t) {
    let e = r(t).name;
    return o(e);
  }, "__wbg_name_d09e9b472d8320d3"), __wbg_new_02d162bc6cf02f60: /* @__PURE__ */ __name(function() {
    let t = new Object();
    return o(t);
  }, "__wbg_new_02d162bc6cf02f60"), __wbg_new_070df68d66325372: /* @__PURE__ */ __name(function() {
    return o(/* @__PURE__ */ new Map());
  }, "__wbg_new_070df68d66325372"), __wbg_new_0_2722fcdb71a888a6: /* @__PURE__ */ __name(function() {
    return o(/* @__PURE__ */ new Date());
  }, "__wbg_new_0_2722fcdb71a888a6"), __wbg_new_1f236d63ba0c4784: /* @__PURE__ */ __name(function(t, e) {
    let n = new Error(y(t, e));
    return o(n);
  }, "__wbg_new_1f236d63ba0c4784"), __wbg_new_227d7c05414eb861: /* @__PURE__ */ __name(function() {
    let t = new Error();
    return o(t);
  }, "__wbg_new_227d7c05414eb861"), __wbg_new_310879b66b6e95e1: /* @__PURE__ */ __name(function() {
    let t = new Array();
    return o(t);
  }, "__wbg_new_310879b66b6e95e1"), __wbg_new_7ddec6de44ff8f5d: /* @__PURE__ */ __name(function(t) {
    let e = new Uint8Array(r(t));
    return o(e);
  }, "__wbg_new_7ddec6de44ff8f5d"), __wbg_new_ee0be486d8f01282: /* @__PURE__ */ __name(function() {
    return a(function() {
      let t = new Headers();
      return o(t);
    }, arguments);
  }, "__wbg_new_ee0be486d8f01282"), __wbg_new_typed_c072c4ce9a2a0cdf: /* @__PURE__ */ __name(function(t, e) {
    try {
      var n = { a: t, b: e }, i = /* @__PURE__ */ __name((d, w) => {
        let m = n.a;
        n.a = 0;
        try {
          return ot(m, n.b, d, w);
        } finally {
          n.a = m;
        }
      }, "i");
      let f = new Promise(i);
      return o(f);
    } finally {
      n.a = 0;
    }
  }, "__wbg_new_typed_c072c4ce9a2a0cdf"), __wbg_new_with_byte_offset_and_length_a87e79143162d67f: /* @__PURE__ */ __name(function(t, e, n) {
    let i = new Uint8Array(r(t), e >>> 0, n >>> 0);
    return o(i);
  }, "__wbg_new_with_byte_offset_and_length_a87e79143162d67f"), __wbg_new_with_length_99887c91eae4abab: /* @__PURE__ */ __name(function(t) {
    let e = new Uint8Array(t >>> 0);
    return o(e);
  }, "__wbg_new_with_length_99887c91eae4abab"), __wbg_new_with_opt_buffer_source_and_init_b007ac889af621a0: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = new Response(r(t), r(e));
      return o(n);
    }, arguments);
  }, "__wbg_new_with_opt_buffer_source_and_init_b007ac889af621a0"), __wbg_new_with_opt_readable_stream_and_init_802af9500a04b75d: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      let n = new Response(r(t), r(e));
      return o(n);
    }, arguments);
  }, "__wbg_new_with_opt_readable_stream_and_init_802af9500a04b75d"), __wbg_new_with_opt_str_and_init_1dd0a9ed589dcc68: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n) {
      let i = new Response(t === 0 ? void 0 : y(t, e), r(n));
      return o(i);
    }, arguments);
  }, "__wbg_new_with_opt_str_and_init_1dd0a9ed589dcc68"), __wbg_new_with_str_and_init_ffe9977c986ea039: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n) {
      let i = new Request(y(t, e), r(n));
      return o(i);
    }, arguments);
  }, "__wbg_new_with_str_and_init_ffe9977c986ea039"), __wbg_next_2a4e19f4f5083b0f: /* @__PURE__ */ __name(function(t) {
    let e = r(t).next;
    return o(e);
  }, "__wbg_next_2a4e19f4f5083b0f"), __wbg_next_6429a146bf756f93: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).next();
      return o(e);
    }, arguments);
  }, "__wbg_next_6429a146bf756f93"), __wbg_node_84ea875411254db1: /* @__PURE__ */ __name(function(t) {
    let e = r(t).node;
    return o(e);
  }, "__wbg_node_84ea875411254db1"), __wbg_prepare_faefb39d63d9c2f1: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n) {
      let i = r(t).prepare(y(e, n));
      return o(i);
    }, arguments);
  }, "__wbg_prepare_faefb39d63d9c2f1"), __wbg_process_44c7a14e11e9f69e: /* @__PURE__ */ __name(function(t) {
    let e = r(t).process;
    return o(e);
  }, "__wbg_process_44c7a14e11e9f69e"), __wbg_prototypesetcall_5f9bdc8d75e07276: /* @__PURE__ */ __name(function(t, e, n) {
    Uint8Array.prototype.set.call(q(t, e), r(n));
  }, "__wbg_prototypesetcall_5f9bdc8d75e07276"), __wbg_push_b77c476b01548d0a: /* @__PURE__ */ __name(function(t, e) {
    return r(t).push(r(e));
  }, "__wbg_push_b77c476b01548d0a"), __wbg_queueMicrotask_78d584b53af520f5: /* @__PURE__ */ __name(function(t) {
    let e = r(t).queueMicrotask;
    return o(e);
  }, "__wbg_queueMicrotask_78d584b53af520f5"), __wbg_queueMicrotask_b39ea83c7f01971a: /* @__PURE__ */ __name(function(t) {
    queueMicrotask(r(t));
  }, "__wbg_queueMicrotask_b39ea83c7f01971a"), __wbg_randomFillSync_6c25eac9869eb53c: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      r(t).randomFillSync(l(e));
    }, arguments);
  }, "__wbg_randomFillSync_6c25eac9869eb53c"), __wbg_read_254bf22401498310: /* @__PURE__ */ __name(function(t) {
    let e = r(t).read();
    return o(e);
  }, "__wbg_read_254bf22401498310"), __wbg_releaseLock_65f356509fef84ac: /* @__PURE__ */ __name(function(t) {
    r(t).releaseLock();
  }, "__wbg_releaseLock_65f356509fef84ac"), __wbg_require_b4edbdcf3e2a1ef0: /* @__PURE__ */ __name(function() {
    return a(function() {
      let t = module.require;
      return o(t);
    }, arguments);
  }, "__wbg_require_b4edbdcf3e2a1ef0"), __wbg_resolve_d17db9352f5a220e: /* @__PURE__ */ __name(function(t) {
    let e = Promise.resolve(r(t));
    return o(e);
  }, "__wbg_resolve_d17db9352f5a220e"), __wbg_respond_0196e052b003e1db: /* @__PURE__ */ __name(function() {
    return a(function(t, e) {
      r(t).respond(e >>> 0);
    }, arguments);
  }, "__wbg_respond_0196e052b003e1db"), __wbg_results_c65f55871a9fa6ec: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).results;
      return g(e) ? 0 : o(e);
    }, arguments);
  }, "__wbg_results_c65f55871a9fa6ec"), __wbg_run_052846663739b2b2: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).run();
      return o(e);
    }, arguments);
  }, "__wbg_run_052846663739b2b2"), __wbg_scheduledTime_8b1bfbedf2b74149: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      return r(t).scheduledTime;
    }, arguments);
  }, "__wbg_scheduledTime_8b1bfbedf2b74149"), __wbg_set_24d0fa9e104112f9: /* @__PURE__ */ __name(function(t, e, n) {
    r(t).set(q(e, n));
  }, "__wbg_set_24d0fa9e104112f9"), __wbg_set_6be42768c690e380: /* @__PURE__ */ __name(function(t, e, n) {
    r(t)[l(e)] = l(n);
  }, "__wbg_set_6be42768c690e380"), __wbg_set_a0e911be3da02782: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n) {
      return Reflect.set(r(t), r(e), r(n));
    }, arguments);
  }, "__wbg_set_a0e911be3da02782"), __wbg_set_body_7f56457720e81672: /* @__PURE__ */ __name(function(t, e) {
    r(t).body = r(e);
  }, "__wbg_set_body_7f56457720e81672"), __wbg_set_cache_9ed01a3813d96de2: /* @__PURE__ */ __name(function(t, e) {
    r(t).cache = ct[e];
  }, "__wbg_set_cache_9ed01a3813d96de2"), __wbg_set_criticalError_d8a6b9f28ecd40df: /* @__PURE__ */ __name(function(t, e) {
    r(t).criticalError = e !== 0;
  }, "__wbg_set_criticalError_d8a6b9f28ecd40df"), __wbg_set_d57e5106f0271787: /* @__PURE__ */ __name(function() {
    return a(function(t, e, n, i, f) {
      r(t).set(y(e, n), y(i, f));
    }, arguments);
  }, "__wbg_set_d57e5106f0271787"), __wbg_set_facb7a5914e0fa39: /* @__PURE__ */ __name(function(t, e, n) {
    let i = r(t).set(r(e), r(n));
    return o(i);
  }, "__wbg_set_facb7a5914e0fa39"), __wbg_set_headers_179cf42797c4a305: /* @__PURE__ */ __name(function(t, e) {
    r(t).headers = r(e);
  }, "__wbg_set_headers_179cf42797c4a305"), __wbg_set_headers_97ed66619adb1e3e: /* @__PURE__ */ __name(function(t, e) {
    r(t).headers = r(e);
  }, "__wbg_set_headers_97ed66619adb1e3e"), __wbg_set_instanceId_84eed47796a1e874: /* @__PURE__ */ __name(function(t, e) {
    r(t).instanceId = e >>> 0;
  }, "__wbg_set_instanceId_84eed47796a1e874"), __wbg_set_method_4d69a1a7e34c0aca: /* @__PURE__ */ __name(function(t, e, n) {
    r(t).method = y(e, n);
  }, "__wbg_set_method_4d69a1a7e34c0aca"), __wbg_set_redirect_1c5253448ef852a8: /* @__PURE__ */ __name(function(t, e) {
    r(t).redirect = ut[e];
  }, "__wbg_set_redirect_1c5253448ef852a8"), __wbg_set_status_0ec29746ab53cab4: /* @__PURE__ */ __name(function(t, e) {
    r(t).status = e;
  }, "__wbg_set_status_0ec29746ab53cab4"), __wbg_stack_3b0d974bbf31e44f: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e).stack, i = x(n, s.__wbindgen_export, s.__wbindgen_export2), f = p;
    b().setInt32(t + 4, f, true), b().setInt32(t + 0, i, true);
  }, "__wbg_stack_3b0d974bbf31e44f"), __wbg_static_accessor_GLOBAL_THIS_02344c9b09eb08a9: /* @__PURE__ */ __name(function() {
    let t = typeof globalThis > "u" ? null : globalThis;
    return g(t) ? 0 : o(t);
  }, "__wbg_static_accessor_GLOBAL_THIS_02344c9b09eb08a9"), __wbg_static_accessor_GLOBAL_ac6d4ac874d5cd54: /* @__PURE__ */ __name(function() {
    let t = typeof global > "u" ? null : global;
    return g(t) ? 0 : o(t);
  }, "__wbg_static_accessor_GLOBAL_ac6d4ac874d5cd54"), __wbg_static_accessor_INIT_STATE_7aac697f52d7cd44: /* @__PURE__ */ __name(function() {
    return o($);
  }, "__wbg_static_accessor_INIT_STATE_7aac697f52d7cd44"), __wbg_static_accessor_SELF_9b2406c23aeb2023: /* @__PURE__ */ __name(function() {
    let t = typeof self > "u" ? null : self;
    return g(t) ? 0 : o(t);
  }, "__wbg_static_accessor_SELF_9b2406c23aeb2023"), __wbg_static_accessor_WINDOW_b34d2126934e16ba: /* @__PURE__ */ __name(function() {
    let t = typeof window > "u" ? null : window;
    return g(t) ? 0 : o(t);
  }, "__wbg_static_accessor_WINDOW_b34d2126934e16ba"), __wbg_status_0853c9f5752c7ee2: /* @__PURE__ */ __name(function(t) {
    return r(t).status;
  }, "__wbg_status_0853c9f5752c7ee2"), __wbg_subarray_7c6a0da8f3b4a1ba: /* @__PURE__ */ __name(function(t, e, n) {
    let i = r(t).subarray(e >>> 0, n >>> 0);
    return o(i);
  }, "__wbg_subarray_7c6a0da8f3b4a1ba"), __wbg_text_c4b3ac0bd8b9d0dd: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).text();
      return o(e);
    }, arguments);
  }, "__wbg_text_c4b3ac0bd8b9d0dd"), __wbg_then_837494e384b37459: /* @__PURE__ */ __name(function(t, e) {
    let n = r(t).then(r(e));
    return o(n);
  }, "__wbg_then_837494e384b37459"), __wbg_then_bd927500e8905df2: /* @__PURE__ */ __name(function(t, e, n) {
    let i = r(t).then(r(e), r(n));
    return o(i);
  }, "__wbg_then_bd927500e8905df2"), __wbg_url_f1cddff1f5b9519a: /* @__PURE__ */ __name(function(t, e) {
    let n = r(e).url, i = x(n, s.__wbindgen_export, s.__wbindgen_export2), f = p;
    b().setInt32(t + 4, f, true), b().setInt32(t + 0, i, true);
  }, "__wbg_url_f1cddff1f5b9519a"), __wbg_value_9cc0518af87a489c: /* @__PURE__ */ __name(function(t) {
    let e = r(t).value;
    return o(e);
  }, "__wbg_value_9cc0518af87a489c"), __wbg_versions_276b2795b1c6a219: /* @__PURE__ */ __name(function(t) {
    let e = r(t).versions;
    return o(e);
  }, "__wbg_versions_276b2795b1c6a219"), __wbg_view_1b637c097280508c: /* @__PURE__ */ __name(function(t) {
    let e = r(t).view;
    return g(e) ? 0 : o(e);
  }, "__wbg_view_1b637c097280508c"), __wbg_webSocket_09cce4e1ce833134: /* @__PURE__ */ __name(function() {
    return a(function(t) {
      let e = r(t).webSocket;
      return g(e) ? 0 : o(e);
    }, arguments);
  }, "__wbg_webSocket_09cce4e1ce833134"), __wbindgen_cast_0000000000000001: /* @__PURE__ */ __name(function(t, e) {
    let n = G(t, e, _t);
    return o(n);
  }, "__wbindgen_cast_0000000000000001"), __wbindgen_cast_0000000000000002: /* @__PURE__ */ __name(function(t, e) {
    let n = G(t, e, it);
    return o(n);
  }, "__wbindgen_cast_0000000000000002"), __wbindgen_cast_0000000000000003: /* @__PURE__ */ __name(function(t) {
    return o(t);
  }, "__wbindgen_cast_0000000000000003"), __wbindgen_cast_0000000000000004: /* @__PURE__ */ __name(function(t) {
    return o(t);
  }, "__wbindgen_cast_0000000000000004"), __wbindgen_cast_0000000000000005: /* @__PURE__ */ __name(function(t, e) {
    let n = q(t, e);
    return o(n);
  }, "__wbindgen_cast_0000000000000005"), __wbindgen_cast_0000000000000006: /* @__PURE__ */ __name(function(t, e) {
    let n = y(t, e);
    return o(n);
  }, "__wbindgen_cast_0000000000000006"), __wbindgen_cast_0000000000000007: /* @__PURE__ */ __name(function(t) {
    let e = BigInt.asUintN(64, t);
    return o(e);
  }, "__wbindgen_cast_0000000000000007"), __wbindgen_object_clone_ref: /* @__PURE__ */ __name(function(t) {
    let e = r(t);
    return o(e);
  }, "__wbindgen_object_clone_ref"), __wbindgen_object_drop_ref: /* @__PURE__ */ __name(function(t) {
    l(t);
  }, "__wbindgen_object_drop_ref") } };
}
__name(et, "et");
function c() {
  if (nt) {
    D();
    return;
  }
}
__name(c, "c");
function _t(_2, t, e) {
  c(), s.__wasm_bindgen_func_elem_963(_2, t, o(e));
}
__name(_t, "_t");
function it(_2, t, e) {
  try {
    let f = s.__wbindgen_add_to_stack_pointer(-16);
    c(), s.__wasm_bindgen_func_elem_1935(f, _2, t, o(e));
    var n = b().getInt32(f + 0, true), i = b().getInt32(f + 4, true);
    if (i) throw l(n);
  } finally {
    s.__wbindgen_add_to_stack_pointer(16);
  }
}
__name(it, "it");
function ot(_2, t, e, n) {
  c(), s.__wasm_bindgen_func_elem_1937(_2, t, o(e), o(n));
}
__name(ot, "ot");
var st = ["bytes"];
var ct = ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"];
var ut = ["follow", "error", "manual"];
var u = 0;
var ft = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: _2, instance: t }) => {
  t === u && s.__wbg_containerstartupoptions_free(_2, 1);
});
var at = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: _2, instance: t }) => {
  t === u && s.__wbg_intounderlyingbytesource_free(_2, 1);
});
var bt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: _2, instance: t }) => {
  t === u && s.__wbg_intounderlyingsink_free(_2, 1);
});
var dt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: _2, instance: t }) => {
  t === u && s.__wbg_intounderlyingsource_free(_2, 1);
});
var H = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: _2, instance: t }) => {
  t === u && s.__wbg_minifyconfig_free(_2, 1);
});
var gt = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry(({ ptr: _2, instance: t }) => {
  t === u && s.__wbg_r2range_free(_2, 1);
});
function o(_2) {
  R === h.length && h.push(h.length + 1);
  let t = R;
  return R = h[t], h[t] = _2, t;
}
__name(o, "o");
var J = typeof FinalizationRegistry > "u" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry((_2) => {
  _2.instance === u && s.__wbindgen_export5(_2.a, _2.b);
});
function L(_2) {
  let t = typeof _2;
  if (t == "number" || t == "boolean" || _2 == null) return `${_2}`;
  if (t == "string") return `"${_2}"`;
  if (t == "symbol") {
    let i = _2.description;
    return i == null ? "Symbol" : `Symbol(${i})`;
  }
  if (t == "function") {
    let i = _2.name;
    return typeof i == "string" && i.length > 0 ? `Function(${i})` : "Function";
  }
  if (Array.isArray(_2)) {
    let i = _2.length, f = "[";
    i > 0 && (f += L(_2[0]));
    for (let d = 1; d < i; d++) f += ", " + L(_2[d]);
    return f += "]", f;
  }
  let e = /\[object ([^\]]+)\]/.exec(toString.call(_2)), n;
  if (e && e.length > 1) n = e[1];
  else return toString.call(_2);
  if (n == "Object") try {
    return "Object(" + JSON.stringify(_2) + ")";
  } catch {
    return "Object";
  }
  return _2 instanceof Error ? `${_2.name}: ${_2.message}
${_2.stack}` : n;
}
__name(L, "L");
function wt(_2) {
  _2 < 1028 || (h[_2] = R, R = _2);
}
__name(wt, "wt");
function lt(_2, t) {
  _2 = _2 >>> 0;
  let e = b(), n = [];
  for (let i = _2; i < _2 + 4 * t; i += 4) n.push(l(e.getUint32(i, true)));
  return n;
}
__name(lt, "lt");
function q(_2, t) {
  return _2 = _2 >>> 0, T().subarray(_2 / 1, _2 / 1 + t);
}
__name(q, "q");
var v = null;
function b() {
  return (v === null || v.buffer.detached === true || v.buffer.detached === void 0 && v.buffer !== s.memory.buffer) && (v = new DataView(s.memory.buffer)), v;
}
__name(b, "b");
function y(_2, t) {
  return ht(_2 >>> 0, t);
}
__name(y, "y");
var z = null;
function T() {
  return (z === null || z.byteLength === 0) && (z = new Uint8Array(s.memory.buffer)), z;
}
__name(T, "T");
function r(_2) {
  return h[_2];
}
__name(r, "r");
function a(_2, t) {
  try {
    return _2.apply(this, t);
  } catch (e) {
    s.__wbindgen_export3(o(e));
  }
}
__name(a, "a");
var h = new Array(1024).fill(void 0);
h.push(void 0, null, true, false);
var R = h.length;
function g(_2) {
  return _2 == null;
}
__name(g, "g");
function G(_2, t, e) {
  let n = { a: _2, b: t, cnt: 1, instance: u }, i = /* @__PURE__ */ __name((...f) => {
    if (n.instance !== u) throw new Error("Cannot invoke closure from previous WASM instance");
    n.cnt++;
    let d = n.a;
    n.a = 0;
    try {
      return e(d, n.b, ...f);
    } finally {
      n.a = d, i._wbg_cb_unref();
    }
  }, "i");
  return i._wbg_cb_unref = () => {
    --n.cnt === 0 && (s.__wbindgen_export5(n.a, n.b), n.a = 0, J.unregister(n));
  }, J.register(i, n, n), i;
}
__name(G, "G");
function pt(_2, t) {
  let e = t(_2.length * 4, 4) >>> 0, n = b();
  for (let i = 0; i < _2.length; i++) n.setUint32(e + 4 * i, o(_2[i]), true);
  return p = _2.length, e;
}
__name(pt, "pt");
function x(_2, t, e) {
  if (e === void 0) {
    let w = M.encode(_2), m = t(w.length, 1) >>> 0;
    return T().subarray(m, m + w.length).set(w), p = w.length, m;
  }
  let n = _2.length, i = t(n, 1) >>> 0, f = T(), d = 0;
  for (; d < n; d++) {
    let w = _2.charCodeAt(d);
    if (w > 127) break;
    f[i + d] = w;
  }
  if (d !== n) {
    d !== 0 && (_2 = _2.slice(d)), i = e(i, n, n = d + _2.length * 3, 1) >>> 0;
    let w = T().subarray(i + d, i + n), m = M.encodeInto(_2, w);
    d += m.written, i = e(i, n, d, 1) >>> 0;
  }
  return p = d, i;
}
__name(x, "x");
var nt = false;
function l(_2) {
  let t = r(_2);
  return wt(_2), t;
}
__name(l, "l");
var rt = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
rt.decode();
function ht(_2, t) {
  return rt.decode(T().subarray(_2, _2 + t));
}
__name(ht, "ht");
var M = new TextEncoder();
"encodeInto" in M || (M.encodeInto = function(_2, t) {
  let e = M.encode(_2);
  return t.set(e), { read: _2.length, written: e.length };
});
var p = 0;
var B = new WebAssembly.Instance(K, et());
var s = B.exports;
s.__wbindgen_start();
Error.stackTraceLimit = 100;
var I = Q();
function N() {
  I.criticalError && (console.log("Reinitializing Wasm application"), D(), I.criticalError = false, I.instanceId++);
}
__name(N, "N");
addEventListener("error", (_2) => {
  V(_2.error);
});
function V(_2) {
  _2 instanceof WebAssembly.RuntimeError && (console.error("Critical", _2), I.criticalError = true);
}
__name(V, "V");
var F = class extends mt {
  static {
    __name(this, "F");
  }
};
F.prototype.fetch = function(t) {
  return X.call(this, t, this.env, this.ctx);
};
F.prototype.init = Y;
F.prototype.scheduled = function(t) {
  return Z.call(this, t, this.env, this.ctx);
};
F.prototype.start = tt;
var xt = { set: /* @__PURE__ */ __name((_2, t, e, n) => Reflect.set(_2.instance, t, e, n), "set"), has: /* @__PURE__ */ __name((_2, t) => Reflect.has(_2.instance, t), "has"), deleteProperty: /* @__PURE__ */ __name((_2, t) => Reflect.deleteProperty(_2.instance, t), "deleteProperty"), apply: /* @__PURE__ */ __name((_2, t, e) => Reflect.apply(_2.instance, t, e), "apply"), construct: /* @__PURE__ */ __name((_2, t, e) => Reflect.construct(_2.instance, t, e), "construct"), getPrototypeOf: /* @__PURE__ */ __name((_2) => Reflect.getPrototypeOf(_2.instance), "getPrototypeOf"), setPrototypeOf: /* @__PURE__ */ __name((_2, t) => Reflect.setPrototypeOf(_2.instance, t), "setPrototypeOf"), isExtensible: /* @__PURE__ */ __name((_2) => Reflect.isExtensible(_2.instance), "isExtensible"), preventExtensions: /* @__PURE__ */ __name((_2) => Reflect.preventExtensions(_2.instance), "preventExtensions"), getOwnPropertyDescriptor: /* @__PURE__ */ __name((_2, t) => Reflect.getOwnPropertyDescriptor(_2.instance, t), "getOwnPropertyDescriptor"), defineProperty: /* @__PURE__ */ __name((_2, t, e) => Reflect.defineProperty(_2.instance, t, e), "defineProperty"), ownKeys: /* @__PURE__ */ __name((_2) => Reflect.ownKeys(_2.instance), "ownKeys") };
var j = { construct(_2, t, e) {
  try {
    N();
    let n = { instance: Reflect.construct(_2, t, e), instanceId: I.instanceId, ctor: _2, args: t, newTarget: e };
    return new Proxy(n, { ...xt, get(i, f, d) {
      i.instanceId !== I.instanceId && (i.instance = Reflect.construct(i.ctor, i.args, i.newTarget), i.instanceId = I.instanceId);
      let w = Reflect.get(i.instance, f, d);
      return typeof w != "function" ? w : w.constructor === Function ? new Proxy(w, { apply(m, U, C) {
        N();
        try {
          return m.apply(U, C);
        } catch (P) {
          throw V(P), P;
        }
      } }) : new Proxy(w, { async apply(m, U, C) {
        N();
        try {
          return await m.apply(U, C);
        } catch (P) {
          throw V(P), P;
        }
      } });
    } });
  } catch (n) {
    throw I.criticalError = true, n;
  }
} };
var Ft = new Proxy(F, j);
var jt = new Proxy(S, j);
var St = new Proxy(k, j);
var kt = new Proxy(W, j);
var Wt = new Proxy(A, j);
var At = new Proxy(E, j);
var Ot = new Proxy(O, j);
export {
  jt as ContainerStartupOptions,
  St as IntoUnderlyingByteSource,
  kt as IntoUnderlyingSink,
  Wt as IntoUnderlyingSource,
  At as MinifyConfig,
  Ot as R2Range,
  Ft as default
};
//# sourceMappingURL=shim.js.map
