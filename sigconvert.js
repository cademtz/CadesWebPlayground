var _SIG_HEXREG = '[0-9a-fA-F]{1,2}';
function Sig_ToCstyle(bytes, mask) {
    if (bytes.length != mask.length) {
        return null;
    }
    var out = { bytes: '', mask: '' };
    var lastesc = false;
    for (var i = 0; i < bytes.length; ++i) {
        if (bytes[i] < 0 || bytes[i] > 0xFF) {
            return null;
        }
        var istext = bytes[i] >= 32 /* SPACE */ && bytes[i] <= 126 /* TILDE */;
        var ishex = istext &&
            ((bytes[i] >= 48 /* '0' */ && bytes[i] <= 57 /* '9' */) ||
                (bytes[i] >= 97 /* 'a' */ && bytes[i] <= 102 /* 'f' */) ||
                (bytes[i] >= 65 /* 'A' */ && bytes[i] <= 70 /* 'F' */));
        // If non-text char or screws up previous hex escape
        if (!istext || (lastesc && ishex)) {
            out.bytes += '\\x' + bytes[i].toString(16);
            lastesc = true;
        }
        else {
            out.bytes += String.fromCharCode(bytes[i]);
            lastesc = false;
        }
        out.mask += mask[i] ? 'x' : '?';
    }
    return out;
}
function Sig_ToIDAstyle(bytes, mask) {
    if (bytes.length != mask.length) {
        return null;
    }
    var out = '';
    for (var i = 0; i < bytes.length; ++i) {
        if (mask[i]) {
            if (bytes[i] < 0 || bytes[i] > 0xFF) {
                return null;
            }
            var intstr = bytes[i].toString(16).toUpperCase();
            if (intstr.length < 2) {
                intstr = '0' + intstr;
            }
            out += intstr;
        }
        else {
            out += '?';
        }
        if (i < bytes.length + 1) {
            out += ' ';
        }
    }
    return out;
}
function _Sig_CalcEscape(str, pos) {
    if (pos < 0 || pos >= str.length ||
        str[pos] != '\\' || ++pos >= str.length) {
        return null;
    }
    var out = { val: 0, len: 2 };
    if (str[pos] == '0') {
        out.val = 0;
    }
    else if (str[pos] == 'x') {
        if (++pos >= str.length) {
            return null;
        }
        var match = str.substr(pos).match(_SIG_HEXREG);
        if (match == null || match.length < 1 ||
            (out.val = parseInt(match[0], 16)) == null) {
            return null;
        }
        out.len += match[0].length;
    }
    return out;
}
function Sig_FromCstyle(bytes, mask) {
    var out = { bytes: [], mask: [] };
    for (var i = 0; i < bytes.length; ++i) {
        if (bytes[i] == '\\') {
            var esc = _Sig_CalcEscape(bytes, i);
            if (esc == null || esc.val < 0 || esc.val > 0xFF) {
                return null;
            }
            out.bytes.push(esc.val);
            i += esc.len - 1;
        }
        else {
            var num = bytes.charCodeAt(i);
            if (num < 0 || num > 0xFF) {
                return null;
            }
            out.bytes.push(num);
        }
    }
    if (mask.length != out.bytes.length) {
        return null;
    }
    for (var i = 0; i < mask.length; ++i) {
        out.mask.push(mask[i] != '?');
    }
    return out;
}
function Sig_FromIDAstyle(bytes) {
    var out = { bytes: [], mask: [] };
    for (var i = 0; i < bytes.length; ++i) {
        if (bytes[i] == ' ') {
            continue;
        }
        else if (bytes[i] == '?') {
            out.bytes.push(63 /* '?' */);
            out.mask.push(false);
            if (i + 1 < bytes.length && bytes[i + 1] == '?') {
                ++i; // Skip double-questionmark style (ex: '48 83 ec ?? c3')
            }
        }
        else {
            var match = bytes.substr(i).match(_SIG_HEXREG);
            var num;
            if (match == null || match.length < 1 ||
                (num = parseInt(match[0], 16)) == null) {
                return null;
            }
            console.log(match[0] + ", " + num.toString(16));
            out.bytes.push(num);
            out.mask.push(true);
            i += match.length /*- 1*/;
        }
    }
    return out;
}
function _Sig_GetIDAstyle() {
    return document.getElementById('idastyle');
}
function _Sig_GetCstyle() {
    return document.getElementById('cstyle');
}
function _Sig_GetMask() {
    return document.getElementById('mask');
}
function _Sig_UpdateAll(sig) {
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
function Sig_OnEdit(caller) {
    var cstyle = _Sig_GetCstyle();
    var mask = _Sig_GetMask();
    var idastyle = _Sig_GetIDAstyle();
    var sig = null;
    var csig = null;
    var idasig = null;
    if (caller == 'cstyle' || caller == 'mask') {
        sig = Sig_FromCstyle(cstyle.value, mask.value);
    }
    else if (caller == 'idastyle') {
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
    if (caller != 'cstyle') {
        cstyle.value = csig.bytes;
    }
    if (caller != 'mask') {
        mask.value = csig.mask;
    }
    if (caller != 'idastyle') {
        idastyle.value = idasig;
    }
}
