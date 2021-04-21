type jssig_t = {
  bytes: number[];
  mask: boolean[];
};

type csig_t = {
  bytes: string;
  mask: string;
};

const _SIG_HEXREG = "[0-9a-fA-F]{1,2}";
var _Sig_usechars = false;

function Sig_ToCstyle(bytes: number[], mask: boolean[]): csig_t | null {
  if (bytes.length != mask.length) {
    return null;
  }

  var out: csig_t = { bytes: "", mask: "" };
  var lastesc = false;

  for (var i = 0; i < bytes.length; ++i) {
    if (bytes[i] < 0 || bytes[i] > 0xff) {
      return null;
    }

    var istext =
      _Sig_usechars &&
      bytes[i] >= 32 /* SPACE */ &&
      bytes[i] <= 126; /* TILDE */
    var ishex =
      istext &&
      ((bytes[i] >= 48 /* '0' */ && bytes[i] <= 57) /* '9' */ ||
        (bytes[i] >= 97 /* 'a' */ && bytes[i] <= 102) /* 'f' */ ||
        (bytes[i] >= 65 /* 'A' */ && bytes[i] <= 70) /* 'F' */);
    // If non-text char or screws up previous hex escape
    if (!istext || (lastesc && ishex)) {
      out.bytes += "\\x" + bytes[i].toString(16);
      lastesc = true;
    } else {
      out.bytes += String.fromCharCode(bytes[i]);
      lastesc = false;
    }
    out.mask += mask[i] ? "x" : "?";
  }

  return out;
}

function Sig_ToIDAstyle(bytes: number[], mask: boolean[]): string | null {
  if (bytes.length != mask.length) {
    return null;
  }

  var out = "";

  for (var i = 0; i < bytes.length; ++i) {
    if (mask[i]) {
      if (bytes[i] < 0 || bytes[i] > 0xff) {
        return null;
      }
      var intstr = bytes[i].toString(16).toUpperCase();
      if (intstr.length < 2) {
        intstr = "0" + intstr;
      }

      out += intstr;
    } else {
      out += "?";
    }

    if (i < bytes.length + 1) {
      out += " ";
    }
  }

  return out;
}

function _Sig_CalcEscape(
  str: string,
  pos: number
): { val: number; len: number } | null {
  if (pos < 0 || pos >= str.length || str[pos] != "\\" || ++pos >= str.length) {
    return null;
  }

  var out = { val: 0, len: 2 };
  if (str[pos] == "0") {
    out.val = 0;
  } else if (str[pos] == "x") {
    if (++pos >= str.length) {
      return null;
    }

    var match = str.substr(pos).match(_SIG_HEXREG);
    if (
      match == null ||
      match.length < 1 ||
      (out.val = parseInt(match[0], 16)) == null
    ) {
      return null;
    }

    out.len += match[0].length;
  }

  return out;
}

function Sig_FromCstyle(bytes: string, mask: string): jssig_t | null {
  var out: jssig_t = { bytes: [], mask: [] };
  for (var i = 0; i < bytes.length; ++i) {
    if (bytes[i] == "\\") {
      var esc = _Sig_CalcEscape(bytes, i);
      if (esc == null || esc.val < 0 || esc.val > 0xff) {
        return null;
      }

      out.bytes.push(esc.val);
      i += esc.len - 1;
    } else {
      var num = bytes.charCodeAt(i);
      if (num < 0 || num > 0xff) {
        return null;
      }

      out.bytes.push(num);
    }
  }

  if (mask.length != out.bytes.length) {
    return null;
  }

  for (var i = 0; i < mask.length; ++i) {
    out.mask.push(mask[i] != "?");
  }

  return out;
}

function Sig_FromIDAstyle(bytes: string): jssig_t | null {
  var out: jssig_t = { bytes: [], mask: [] };
  for (var i = 0; i < bytes.length; ++i) {
    if (bytes[i] == " ") {
      continue;
    } else if (bytes[i] == "?") {
      out.bytes.push(63 /* '?' */);
      out.mask.push(false);

      if (i + 1 < bytes.length && bytes[i + 1] == "?") {
        ++i; // Skip double-questionmark style (ex: '48 83 ec ?? c3')
      }
    } else {
      var match = bytes.substr(i).match(_SIG_HEXREG);
      var num: number;

      if (
        match == null ||
        match.length < 1 ||
        (num = parseInt(match[0], 16)) == null
      ) {
        return null;
      }

      out.bytes.push(num);
      out.mask.push(true);
      i += match.length /*- 1*/;
    }
  }

  return out;
}

function _Sig_GetIDAstyle(): HTMLInputElement {
  return <HTMLInputElement>document.getElementById("idastyle");
}
function _Sig_GetCstyle(): HTMLInputElement {
  return <HTMLInputElement>document.getElementById("cstyle");
}
function _Sig_GetMask(): HTMLInputElement {
  return <HTMLInputElement>document.getElementById("mask");
}
function _Sig_GetUseChars(): HTMLInputElement {
  return <HTMLInputElement>document.getElementById("usechars");
}

function _Sig_UpdateAll(sig: jssig_t): void {
  var csig = Sig_ToCstyle(sig.bytes, sig.mask);
  var idasig = Sig_ToIDAstyle(sig.bytes, sig.mask);

  if (csig != null) {
    _Sig_GetCstyle().value = csig.bytes;
    _Sig_GetMask().value = csig.mask;
  }

  if (idasig != null) {
    _Sig_GetIDAstyle().value = idasig;
  }
}

function Sig_OnEdit(caller: string): void {
  var cstyle = _Sig_GetCstyle();
  var mask = _Sig_GetMask();
  var idastyle = _Sig_GetIDAstyle();

  var sig: jssig_t = null;
  var csig: csig_t = null;
  var idasig: string = null;

  if (caller == "cstyle" || caller == "mask") {
    sig = Sig_FromCstyle(cstyle.value, mask.value);
  } else {
    if (caller == "usechars") {
      _Sig_usechars = _Sig_GetUseChars().checked;
    }
    sig = Sig_FromIDAstyle(idastyle.value);
  }

  if (sig == null) {
    return;
  }

  csig = Sig_ToCstyle(sig.bytes, sig.mask);
  idasig = Sig_ToIDAstyle(sig.bytes, sig.mask);

  if (csig == null || idasig == null) {
    return;
  }

  if (caller != "cstyle") {
    cstyle.value = csig.bytes;
  }
  if (caller != "mask") {
    mask.value = csig.mask;
  }
  if (caller != "idastyle") {
    idastyle.value = idasig;
  }
}
