// =============================================================================
//  pyx_decomp.cpp  --  Cython / Cython-NDK  C-source  ->  Python  decompiler
// =============================================================================
//
//  Takes a C source produced by Cython (or a Python wrapper embedding such a
//  C source, or a stripped/binary object produced by NDK / gcc) and recovers
//  the *original Python source*.
//
//  Strategy:
//    1. Detect input kind: plain C source / Python wrapper / binary.
//    2. Extract the C source (from r''' ... ''' literal, or strings in .rodata).
//    3. Build a SYMBOL TABLE by parsing:
//         static const char __pyx_k_<NAME>[] = "...";
//         {&__pyx_n_s_<X>, __pyx_k_<Y>, sizeof(...), encoding, is_unicode, is_str}
//         __pyx_tuple_<N>  = PyTuple_Pack(K, ...);
//         __pyx_slice_<N> = PySlice_New(...);
//         __pyx_int_<N>    = PyInt_FromLong(N);
//         __pyx_codeobj_<N> = __Pyx_PyCode_New(argcount, kwcount, nlocals, ...);
//    4. Extract function definitions: __pyx_pf_<M>_<F>(self, arg1, arg2, ...).
//    5. For each function body, run a DEEP-REGEX pattern engine: SSA-style
//       symbolic execution where every __pyx_t_N assignment is rewritten to a
//       Python expression. The engine tries a catalog of (regex, handler)
//       patterns in order until a fixpoint. This is the "DEEP re" technique.
//    6. Extract module-level statements from __pyx_pymod_exec_<module> in
//       source order, decoding each the same way.
//    7. Emit pretty-printed Python.
//    8. For stripped binaries: scan .rodata for printable strings, identify
//       PyInit_<module>, Python identifiers, source .py filenames, and
//       long base64 blobs; emit a best-effort skeleton.
//
//  Build:
//      g++ -std=c++17 -O2 -o pyx_decomp pyx_decomp.cpp -lz -lbz2
//
//  Usage:
//      ./pyx_decomp <input.c|input.py|input.so|input.bin> [-o output.py]
//                   [--json report.json] [--debug]
//
// =============================================================================

#include <zlib.h>
#include <bzlib.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace pyx {

// ---------------------------------------------------------------------------
//  Small string utilities
// ---------------------------------------------------------------------------

static std::string slurp_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::string();
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

static std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && std::isspace((unsigned char)s[a])) ++a;
  while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
  return s.substr(a, b - a);
}

static std::string strip_cr(const std::string& s) {
  std::string r;
  r.reserve(s.size());
  for (char c : s)
    if (c != '\r') r.push_back(c);
  return r;
}

static bool starts_with(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && std::equal(p.begin(), p.end(), s.begin());
}

static bool ends_with(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && std::equal(p.rbegin(), p.rend(), s.rbegin());
}

static std::string replace_all(std::string s, const std::string& from,
                               const std::string& to) {
  if (from.empty()) return s;
  size_t p = 0;
  while ((p = s.find(from, p)) != std::string::npos) {
    s.replace(p, from.size(), to);
    p += to.size();
  }
  return s;
}

// Unescape a C string literal body (between quotes already stripped).
static std::string unescape_c_string(const std::string& lit) {
  std::string out;
  out.reserve(lit.size());
  for (size_t i = 0; i < lit.size(); ++i) {
    char c = lit[i];
    if (c != '\\') { out.push_back(c); continue; }
    if (++i >= lit.size()) break;
    char e = lit[i];
    switch (e) {
      case 'a': out.push_back('\a'); break;
      case 'b': out.push_back('\b'); break;
      case 'f': out.push_back('\f'); break;
      case 'n': out.push_back('\n'); break;
      case 'r': out.push_back('\r'); break;
      case 't': out.push_back('\t'); break;
      case 'v': out.push_back('\v'); break;
      case '\\': out.push_back('\\'); break;
      case '"': out.push_back('"'); break;
      case '\'': out.push_back('\''); break;
      case '?': out.push_back('?'); break;
      case 'x': {
        size_t j = i + 1;
        std::string hex;
        while (j < lit.size() && hex.size() < 2 && std::isxdigit((unsigned char)lit[j])) hex.push_back(lit[j++]);
        if (!hex.empty()) { out.push_back((char)std::stoi(hex, nullptr, 16)); i = j - 1; }
        break;
      }
      case 'u': {
        size_t j = i + 1;
        std::string hex;
        while (j < lit.size() && hex.size() < 4 && std::isxdigit((unsigned char)lit[j])) hex.push_back(lit[j++]);
        if (!hex.empty()) {
          unsigned cp = (unsigned)std::stoul(hex, nullptr, 16);
          if (cp < 0x80) out.push_back((char)cp);
          else if (cp < 0x800) {
            out.push_back((char)(0xC0 | (cp >> 6)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
          } else {
            out.push_back((char)(0xE0 | (cp >> 12)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
          }
          i = j - 1;
        }
        break;
      }
      case 'U': {
        size_t j = i + 1;
        std::string hex;
        while (j < lit.size() && hex.size() < 8 && std::isxdigit((unsigned char)lit[j])) hex.push_back(lit[j++]);
        if (!hex.empty()) {
          unsigned cp = (unsigned)std::stoul(hex, nullptr, 16);
          if (cp < 0x10000) {
            if (cp < 0x80) out.push_back((char)cp);
            else if (cp < 0x800) {
              out.push_back((char)(0xC0 | (cp >> 6)));
              out.push_back((char)(0x80 | (cp & 0x3F)));
            } else {
              out.push_back((char)(0xE0 | (cp >> 12)));
              out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
              out.push_back((char)(0x80 | (cp & 0x3F)));
            }
          } else {
            out.push_back((char)(0xF0 | (cp >> 18)));
            out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back((char)(0x80 | (cp & 0x3F)));
          }
          i = j - 1;
        }
        break;
      }
      default:
        if (e >= '0' && e <= '7') {
          size_t j = i;
          std::string oct;
          while (j < lit.size() && oct.size() < 3 && lit[j] >= '0' && lit[j] <= '7') oct.push_back(lit[j++]);
          out.push_back((char)std::stoi(oct, nullptr, 8));
          i = j - 1;
        } else {
          out.push_back(e);
        }
    }
  }
  return out;
}

static std::string py_repr(const std::string& s, bool prefer_single = false) {
  bool has_newline = s.find('\n') != std::string::npos;
  bool has_dq = s.find('"') != std::string::npos;
  bool has_sq = s.find('\'') != std::string::npos;

  if (has_newline) {
    if (s.find("\"\"\"") != std::string::npos && s.find("'''") == std::string::npos) {
      return "'''" + s + "'''";
    }
    return "\"\"\"" + s + "\"\"\"";
  }

  char q = prefer_single ? '\'' : '"';
  if (q == '"' && has_dq && !has_sq) q = '\'';
  if (q == '\'' && has_sq && !has_dq) q = '"';

  std::string out;
  out.push_back(q);
  for (char c : s) {
    if (c == q || c == '\\') { out.push_back('\\'); out.push_back(c); }
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else if (c == '\t') out += "\\t";
    else if ((unsigned char)c < 0x20) {
      char buf[8];
      std::snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c);
      out += buf;
    } else out.push_back(c);
  }
  out.push_back(q);
  return out;
}

static std::string py_repr_long(const std::string& s) {
  if (s.size() > 200) {
    if (s.find("'''") != std::string::npos && s.find("\"\"\"") != std::string::npos) {
      return py_repr(s);
    }
    if (s.find("'''") == std::string::npos) return "'''" + s + "'''";
    return "\"\"\"" + s + "\"\"\"";
  }
  return py_repr(s);
}

// ---------------------------------------------------------------------------
//  Symbol table
// ---------------------------------------------------------------------------

enum class SymKind { Str, Bytes, Unicode, Int, Tuple, Slice, CodeObj, Module };

struct Sym {
  SymKind kind = SymKind::Str;
  std::string name;
  std::string py_id;
  std::string str_val;
  long long int_val = 0;
  std::vector<std::string> elements;
  int argcount = 0, kwcount = 0, nlocals = 0, stacksize = 0, flags = 0;
  int firstlineno = 0;
  std::string co_filename;
  std::string co_name;
  std::string py_expr;
  bool resolved = false;
};

struct SymbolTable {
  std::map<std::string, Sym> by_cname;
  std::map<std::string, std::string> k_to_n;
  std::string module_name;
  std::string module_filename;
  std::string module_doc;
  std::set<std::string> builtins_used;
};

// ---------------------------------------------------------------------------
//  Stage 1: Input detection & C-source extraction
// ---------------------------------------------------------------------------

enum class InputKind { CSource, PyWrapper, Binary, Unknown };

struct Input {
  InputKind kind = InputKind::Unknown;
  std::string raw_text;
  std::vector<uint8_t> bin;
  std::string c_source;
  std::string detected_path;
};

static InputKind detect_input_kind(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return InputKind::Unknown;
  char buf[4096];
  in.read(buf, sizeof(buf));
  std::streamsize n = in.gcount();
  if (n < 4) return InputKind::CSource;

  size_t non_text = 0;
  for (std::streamsize i = 0; i < n; ++i) {
    unsigned char c = (unsigned char)buf[i];
    if (c == 0) return InputKind::Binary;
    if (c < 0x09 || (c > 0x0D && c < 0x20)) ++non_text;
  }
  if (non_text * 100 > (size_t)n * 5) return InputKind::Binary;

  std::string head(buf, n);
  if (head.find("C_SOURCE") != std::string::npos &&
      (head.find("import ") != std::string::npos || head.find("r'''") != std::string::npos)) {
    return InputKind::PyWrapper;
  }
  if (head.find("#include") != std::string::npos ||
      head.find("#ifndef") != std::string::npos ||
      head.find("PyMODINIT_FUNC") != std::string::npos ||
      head.find("__pyx_") != std::string::npos) {
    return InputKind::CSource;
  }
  return InputKind::CSource;
}

static bool extract_c_from_py_wrapper(const std::string& text, std::string& out,
                                       std::string& err) {
  size_t eq = text.find("C_SOURCE");
  if (eq == std::string::npos) {
    err = "no C_SOURCE variable found in Python wrapper";
    return false;
  }
  size_t p = eq + 8;
  while (p < text.size() && (text[p] == ' ' || text[p] == '\t')) ++p;
  if (p < text.size() && text[p] == '=') ++p;
  while (p < text.size() && (text[p] == ' ' || text[p] == '\t')) ++p;
  while (p < text.size() &&
         (text[p] == 'r' || text[p] == 'b' || text[p] == 'u' || text[p] == 'f' ||
          text[p] == 'R' || text[p] == 'B' || text[p] == 'U' || text[p] == 'F')) {
    ++p;
  }
  if (p >= text.size()) {
    err = "C_SOURCE declaration is malformed (no opening quote)";
    return false;
  }
  char q = text[p];
  if (q != '\'' && q != '"') {
    err = "C_SOURCE is not a string literal";
    return false;
  }
  bool triple = (p + 2 < text.size() && text[p + 1] == q && text[p + 2] == q);
  size_t body_start, body_end;
  if (triple) {
    body_start = p + 3;
    std::string close(3, q);
    size_t end = text.find(close, body_start);
    if (end == std::string::npos) {
      err = "C_SOURCE triple-quoted string not closed";
      return false;
    }
    body_end = end;
  } else {
    body_start = p + 1;
    size_t end = body_start;
    while (end < text.size()) {
      if (text[end] == '\\' && end + 1 < text.size()) { end += 2; continue; }
      if (text[end] == q) break;
      ++end;
    }
    if (end >= text.size()) {
      err = "C_SOURCE single-quoted string not closed";
      return false;
    }
    body_end = end;
  }
  out = text.substr(body_start, body_end - body_start);
  return true;
}

static std::vector<std::string> extract_strings_from_binary(const std::vector<uint8_t>& bin,
                                                              size_t min_len = 4) {
  std::vector<std::string> out;
  std::string cur;
  for (uint8_t c : bin) {
    if (c >= 0x20 && c < 0x7F) cur.push_back((char)c);
    else {
      if (cur.size() >= min_len) out.push_back(cur);
      cur.clear();
    }
  }
  if (cur.size() >= min_len) out.push_back(cur);
  return out;
}

static Input load_input(const std::string& path, std::string& err) {
  Input in;
  in.detected_path = path;
  in.kind = detect_input_kind(path);
  if (in.kind == InputKind::Binary) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { err = "cannot open file: " + path; return in; }
    std::vector<uint8_t> v((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>());
    in.bin = std::move(v);
    return in;
  }
  in.raw_text = slurp_file(path);
  if (in.raw_text.empty()) { err = "file is empty or unreadable: " + path; return in; }
  in.raw_text = strip_cr(in.raw_text);
  if (in.kind == InputKind::PyWrapper) {
    if (!extract_c_from_py_wrapper(in.raw_text, in.c_source, err)) return in;
  } else {
    in.c_source = in.raw_text;
  }
  return in;
}

// ---------------------------------------------------------------------------
//  Stage 2: Symbol table builder
// ---------------------------------------------------------------------------

static bool parse_c_string_literal(const std::string& s, size_t start,
                                    std::string& body, size_t& end) {
  if (start >= s.size() || (s[start] != '"' && s[start] != '\'')) return false;
  char q = s[start];
  bool triple = (start + 2 < s.size() && s[start + 1] == q && s[start + 2] == q);
  size_t i = start + (triple ? 3 : 1);
  std::string raw;
  while (i < s.size()) {
    char c = s[i];
    if (c == '\\' && i + 1 < s.size()) {
      raw.push_back(c);
      raw.push_back(s[i + 1]);
      i += 2;
      continue;
    }
    if (triple) {
      if (i + 2 < s.size() && s[i] == q && s[i + 1] == q && s[i + 2] == q) {
        i += 3; body = raw; end = i; return true;
      }
      raw.push_back(c); ++i;
    } else {
      if (c == q) { ++i; body = raw; end = i; return true; }
      raw.push_back(c); ++i;
    }
  }
  return false;
}

static void parse_k_constants(const std::string& csrc,
                              std::map<std::string, std::string>& out) {
  static const std::regex re_decl(
      R"(static\s+const\s+char\s+(__pyx_k_[A-Za-z0-9_]+)\s*\[\s*\]\s*=\s*)");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re_decl);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string name = (*it)[1].str();
    size_t after = (size_t)(*it).position() + (*it)[0].length();
    while (after < csrc.size() && std::isspace((unsigned char)csrc[after])) ++after;
    if (after >= csrc.size() || csrc[after] != '"') continue;
    std::string body;
    size_t endpos;
    if (!parse_c_string_literal(csrc, after, body, endpos)) continue;
    out[name] = unescape_c_string(body);
  }
}

static void parse_string_tab(const std::string& csrc, SymbolTable& st) {
  size_t p = csrc.find("__pyx_string_tab[]");
  if (p == std::string::npos) return;
  size_t lb = csrc.find('{', p);
  if (lb == std::string::npos) return;
  size_t rb = csrc.find("};", lb);
  if (rb == std::string::npos) return;
  std::string body = csrc.substr(lb + 1, rb - lb - 1);

  static const std::regex re_entry(
      R"(\{\s*&\s*(__pyx_[a-zA-Z0-9_]+)\s*,\s*(__pyx_k_[A-Za-z0-9_]+)\s*,\s*sizeof\([^)]+\)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\})");
  auto begin = std::sregex_iterator(body.begin(), body.end(), re_entry);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string cname = (*it)[1].str();
    std::string kname = (*it)[2].str();
    int enc = std::stoi((*it)[3].str());
    int is_unicode = std::stoi((*it)[4].str());
    int is_str = std::stoi((*it)[5].str());
    (void)is_str;
    auto kit = st.k_to_n.find(kname);
    if (kit == st.k_to_n.end()) continue;
    Sym s;
    s.name = cname;
    s.str_val = kit->second;
    if (is_unicode) {
      s.kind = SymKind::Unicode;
      s.py_expr = py_repr_long(s.str_val);
    } else if (enc) {
      s.kind = SymKind::Bytes;
      s.py_expr = "b" + py_repr_long(s.str_val);
    } else {
      s.kind = SymKind::Str;
      s.py_expr = py_repr_long(s.str_val);
    }
    s.py_id = s.str_val;
    s.resolved = true;
    st.by_cname[cname] = std::move(s);
  }
}

static void parse_tuples(const std::string& csrc, SymbolTable& st) {
  // Cython tuple names are `__pyx_tuple_<suffix>` where <suffix> is either
  // empty (just `__pyx_tuple_`) or starts with an underscore (`__pyx_tuple__2`,
  // `__pyx_tuple__7`, ...).  Match `__pyx_tuple_` followed by 0+ word chars.
  static const std::regex re(
      R"((__pyx_tuple_[A-Za-z0-9_]*)\s*=\s*PyTuple_Pack\s*\(\s*(\d+)\s*,\s*([^;]+?)\)\s*;)");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string tname = (*it)[1].str();
    int count = std::stoi((*it)[2].str());
    std::string args = (*it)[3].str();
    std::vector<std::string> parts;
    std::string cur;
    int depth = 0;
    for (char c : args) {
      if (c == '(') ++depth;
      if (c == ')') --depth;
      if (c == ',' && depth == 0) { parts.push_back(trim(cur)); cur.clear(); }
      else cur.push_back(c);
    }
    if (!cur.empty()) parts.push_back(trim(cur));
    (void)count;
    Sym s;
    s.name = tname;
    s.kind = SymKind::Tuple;
    s.elements = parts;
    s.resolved = true;
    st.by_cname[tname] = std::move(s);
  }
}

static void parse_slices(const std::string& csrc, SymbolTable& st) {
  // Slice names: `__pyx_slice_<suffix>` -- same convention as tuples.
  static const std::regex re(
      R"((__pyx_slice_[A-Za-z0-9_]*)\s*=\s*PySlice_New\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+?)\)\s*;)");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string sname = (*it)[1].str();
    Sym s;
    s.name = sname;
    s.kind = SymKind::Slice;
    s.elements = {trim((*it)[2].str()), trim((*it)[3].str()), trim((*it)[4].str())};
    s.resolved = true;
    st.by_cname[sname] = std::move(s);
  }
}

static void parse_ints(const std::string& csrc, SymbolTable& st) {
  static const std::regex re(
      R"((__pyx_int_[A-Za-z0-9_]+)\s*=\s*Py(?:Int|Long)_FromLong\s*\(\s*(-?\d+)\s*\)\s*;)");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string name = (*it)[1].str();
    long long val = std::stoll((*it)[2].str());
    Sym s;
    s.name = name;
    s.kind = SymKind::Int;
    s.int_val = val;
    s.py_expr = std::to_string(val);
    s.resolved = true;
    st.by_cname[name] = std::move(s);
  }
}

static void parse_codeobjs(const std::string& csrc, SymbolTable& st) {
  static const std::regex re(
      R"((__pyx_codeobj__[A-Za-z0-9_]+)\s*=\s*\(?\s*\(?\s*PyObject\s*\*\s*\)?\s*__Pyx_PyCode_New\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^,]+)\s*,\s*(\d+)\s*,\s*([^)]+?)\)\s*\)?\s*;)");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string name = (*it)[1].str();
    Sym s;
    s.name = name;
    s.kind = SymKind::CodeObj;
    s.argcount = std::stoi((*it)[2].str());
    s.kwcount = std::stoi((*it)[3].str());
    s.nlocals = std::stoi((*it)[4].str());
    s.stacksize = std::stoi((*it)[5].str());
    std::string filename_ref = trim((*it)[13].str());
    std::string name_ref = trim((*it)[14].str());
    s.firstlineno = std::stoi((*it)[15].str());
    auto f = st.by_cname.find(filename_ref);
    if (f != st.by_cname.end()) s.co_filename = f->second.str_val;
    auto n = st.by_cname.find(name_ref);
    if (n != st.by_cname.end()) s.co_name = n->second.str_val;
    s.resolved = true;
    st.by_cname[name] = std::move(s);
  }
}

static void parse_module_name(const std::string& csrc, SymbolTable& st) {
  static const std::regex re_def(
      R"PYREGEX(struct\s+PyModuleDef\s+__pyx_moduledef\s*=\s*\{\s*PyModuleDef_HEAD_INIT\s*,\s*"([^"]+)"\s*,)PYREGEX");
  std::smatch m;
  if (std::regex_search(csrc, m, re_def)) { st.module_name = m[1].str(); return; }
  static const std::regex re_init(R"(PyInit_([A-Za-z0-9_]+)\s*\()");
  if (std::regex_search(csrc, m, re_init)) { st.module_name = m[1].str(); return; }
  static const std::regex re_mod(R"PYREGEX(__Pyx_MODULE_NAME\s+"([^"]+)")PYREGEX");
  if (std::regex_search(csrc, m, re_mod)) st.module_name = m[1].str();
}

static void parse_source_filename(const std::string& csrc, SymbolTable& st) {
  (void)csrc;
  for (auto& kv : st.k_to_n) {
    if (ends_with(kv.second, ".py") && st.module_filename.empty()) {
      std::string base = kv.second.substr(0, kv.second.size() - 3);
      for (auto& c : base) if (c == '/' || c == '\\') c = '_';
      if (base == st.module_name) { st.module_filename = kv.second; return; }
    }
  }
  for (auto& kv : st.k_to_n) {
    if (ends_with(kv.second, ".py")) { st.module_filename = kv.second; return; }
  }
  st.module_filename = st.module_name + ".py";
}

// Forward declarations for Cython 3.x parsers (defined later in this file).
static void parse_cython3_strings(const std::string& csrc, SymbolTable& st);
static void parse_cython3_tuples(const std::string& csrc, SymbolTable& st);
static void parse_cython3_slices(const std::string& csrc, SymbolTable& st);
static void parse_cython3_ints(const std::string& csrc, SymbolTable& st);

static bool build_symbol_table(const std::string& csrc, SymbolTable& st, std::string& err) {
  parse_cython3_strings(csrc, st);
  parse_k_constants(csrc, st.k_to_n);
  parse_string_tab(csrc, st);
  parse_cython3_tuples(csrc, st);
  parse_cython3_slices(csrc, st);
  parse_cython3_ints(csrc, st);
  parse_tuples(csrc, st);
  parse_slices(csrc, st);
  parse_ints(csrc, st);
  parse_codeobjs(csrc, st);
  parse_module_name(csrc, st);
  parse_source_filename(csrc, st);
  if (st.module_name.empty()) { err = "could not determine module name"; return false; }
  return true;
}

// ---------------------------------------------------------------------------
//  Cython 3.x compressed-string support
// ---------------------------------------------------------------------------
//
// Cython 3.x stores all string constants in a single compressed blob:
//
//   1. The C source has #define mappings like:
//        #define __pyx_n_u_NAME __pyx_string_tab[N]
//        #define __pyx_kp_s_NAME __pyx_string_tab[N]
//        #define __pyx_kp_b_NAME __pyx_string_tab[N]
//      These map each named identifier (e.g. __pyx_n_u_base64) to an index
//      in the string table __pyx_string_tab[].
//
//   2. The string table itself is initialized in __Pyx_InitConstants by:
//        a) decompressing a single bzip2- or zlib-compressed blob `cstring`
//        b) walking an `index` array of {length: 12} structs to slice the
//           decompressed bytes into individual strings
//        c) strings 0..N_unicode-1 are decoded as UTF-8 (PyUnicode_DecodeUTF8)
//           strings N_unicode..N_total-1 are decoded as bytes (PyBytes)
//
//   3. The compressed blob is declared as:
//        #if (CYTHON_COMPRESS_STRINGS) == 2
//        const char* const cstring = "BZh9..." "..." "...";
//        #elif (CYTHON_COMPRESS_STRINGS) != 0
//        const char* const cstring = "x\xDA..." "..." "...";
//        #endif
//      Each "..." segment is up to 2000 chars (compiler limit); they are
//      concatenated by C string-literal juxtaposition.
//
// We support both bzip2 (algo=2) and zlib (algo=1) decompression.

// Decode a C string literal body (between quotes already stripped) into
// raw bytes, handling \NNN (octal), \xNN, \\", \\", \n, \t, \r, \\, etc.
static std::string decode_c_string_literal(const std::string& s) {
  return unescape_c_string(s);
}

// Find the end of a C string statement (the ; after the last ").
// Returns the position of the ;, or std::string::npos if not found.
// `start_inside_string` should be true if `start` is inside a string literal
// (e.g. right after the opening ").
static size_t find_cstring_statement_end(const std::string& body, size_t start,
                                          bool start_inside_string = false) {
  bool in_str = start_inside_string;
  size_t i = start;
  while (i < body.size()) {
    char c = body[i];
    if (in_str) {
      if (c == '\\' && i + 1 < body.size()) { i += 2; continue; }
      if (c == '"') { in_str = false; ++i; continue; }
      ++i; continue;
    }
    if (c == '"') { in_str = true; ++i; continue; }
    // Skip block comment
    if (c == '/' && i + 1 < body.size() && body[i+1] == '*') {
      i += 2;
      while (i + 1 < body.size() && !(body[i] == '*' && body[i+1] == '/')) ++i;
      i += 2; continue;
    }
    // Skip line comment
    if (c == '/' && i + 1 < body.size() && body[i+1] == '/') {
      i += 2;
      while (i < body.size() && body[i] != '\n') ++i;
      continue;
    }
    // Preprocessor line: skip to end of line
    if (c == '#') {
      size_t j = i;
      while (j > 0 && (body[j-1] == ' ' || body[j-1] == '\t')) --j;
      if (j == 0 || body[j-1] == '\n') {
        while (i < body.size() && body[i] != '\n') ++i;
        continue;
      }
    }
    if (c == ';') return i;
    ++i;
  }
  return std::string::npos;
}

// Extract the concatenated body of a C string literal statement.
// `start` should be right AFTER the opening " of the first string part.
// `end` should be the position of the ; (from find_cstring_statement_end).
// Returns the decoded bytes of all concatenated string parts.
static std::string extract_cstring_bytes(const std::string& body, size_t start, size_t end) {
  std::string result;
  size_t i = start;
  bool first = true;
  while (i < end) {
    if (first) {
      // First part: we're already inside the string content. Find the closing ".
      first = false;
      size_t j = i;
      while (j < end) {
        if (body[j] == '\\' && j + 1 < end) { j += 2; continue; }
        if (body[j] == '"') break;
        ++j;
      }
      result += decode_c_string_literal(body.substr(i, j - i));
      i = j + 1;
      continue;
    }
    // Skip whitespace and preprocessor lines
    char c = body[i];
    if (c == '/' && i + 1 < body.size() && body[i+1] == '*') {
      i += 2;
      while (i + 1 < body.size() && !(body[i] == '*' && body[i+1] == '/')) ++i;
      i += 2; continue;
    }
    if (c == '/' && i + 1 < body.size() && body[i+1] == '/') {
      i += 2;
      while (i < end && body[i] != '\n') ++i;
      continue;
    }
    if (c == '#') {
      size_t j = i;
      while (j > 0 && (body[j-1] == ' ' || body[j-1] == '\t')) --j;
      if (j == 0 || body[j-1] == '\n') {
        while (i < end && body[i] != '\n') ++i;
        continue;
      }
    }
    if (c == '"') {
      // Start of a string part — find the closing "
      size_t s = i + 1;
      size_t j = i + 1;
      while (j < end) {
        if (body[j] == '\\' && j + 1 < end) { j += 2; continue; }
        if (body[j] == '"') break;
        ++j;
      }
      result += decode_c_string_literal(body.substr(s, j - s));
      i = j + 1;
      continue;
    }
    ++i;
  }
  return result;
}


static std::vector<std::string> extract_string_literals(const std::string& body,
                                                          size_t start, size_t end) {
  std::vector<std::string> out;
  size_t i = start;
  while (i < end) {
    char c = body[i];
    // Skip block comment
    if (c == '/' && i + 1 < body.size() && body[i+1] == '*') {
      i += 2;
      while (i + 1 < body.size() && !(body[i] == '*' && body[i+1] == '/')) ++i;
      i += 2; continue;
    }
    // Skip line comment
    if (c == '/' && i + 1 < body.size() && body[i+1] == '/') {
      i += 2;
      while (i < end && body[i] != '\n') ++i;
      continue;
    }
    // Skip preprocessor line (if at line start)
    if (c == '#') {
      size_t j = i;
      while (j > 0 && (body[j-1] == ' ' || body[j-1] == '\t')) --j;
      if (j == 0 || body[j-1] == '\n') {
        while (i < end && body[i] != '\n') ++i;
        continue;
      }
    }
    if (c == '"') {
      size_t s = i + 1;
      size_t j = i + 1;
      while (j < end) {
        if (body[j] == '\\' && j + 1 < end) { j += 2; continue; }
        if (body[j] == '"') break;
        ++j;
      }
      out.push_back(body.substr(s, j - s));
      i = j + 1;
      continue;
    }
    ++i;
  }
  return out;
}

// Decompress a zlib stream using libz.
static bool zlib_decompress(const std::string& compressed, std::string& out) {
  z_stream strm;
  memset(&strm, 0, sizeof(strm));
  strm.next_in = (Bytef*)compressed.data();
  strm.avail_in = (uInt)compressed.size();
  if (inflateInit(&strm) != Z_OK) return false;
  out.clear();
  char buf[65536];
  int ret;
  do {
    strm.next_out = (Bytef*)buf;
    strm.avail_out = sizeof(buf);
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
      inflateEnd(&strm);
      return false;
    }
    out.append(buf, sizeof(buf) - strm.avail_out);
  } while (ret != Z_STREAM_END);
  inflateEnd(&strm);
  return true;
}

// Decompress a bzip2 stream using libbz2.
static bool bzip2_decompress(const std::string& compressed, std::string& out) {
  bz_stream strm;
  memset(&strm, 0, sizeof(strm));
  strm.next_in = (char*)compressed.data();
  strm.avail_in = (unsigned int)compressed.size();
  if (BZ2_bzDecompressInit(&strm, 0, 0) != BZ_OK) return false;
  out.clear();
  char buf[65536];
  int ret;
  do {
    strm.next_out = buf;
    strm.avail_out = sizeof(buf);
    ret = BZ2_bzDecompress(&strm);
    if (ret != BZ_OK && ret != BZ_STREAM_END) {
      BZ2_bzDecompressEnd(&strm);
      return false;
    }
    out.append(buf, sizeof(buf) - strm.avail_out);
  } while (ret != BZ_STREAM_END);
  BZ2_bzDecompressEnd(&strm);
  return true;
}

// Parse the Cython 3.x compressed string table.
// See the comment block above for the format. On success, populates st.by_cname
// with each #define'd name (e.g. __pyx_n_u_NAME) mapped to its actual string value.
static void parse_cython3_strings(const std::string& csrc, SymbolTable& st) {
  // Step 1: Find all #define __pyx_<X> __pyx_string_tab[N] mappings.
  static const std::regex re_define(
      R"PYREGEX(#\s*define\s+(__pyx_[a-zA-Z0-9_]+)\s+__pyx_string_tab\[(\d+)\])PYREGEX");
  std::map<std::string, int> name_to_index;
  std::map<int, std::string> index_to_canonical_name;
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re_define);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string name = (*it)[1].str();
    int idx = std::stoi((*it)[2].str());
    name_to_index[name] = idx;
    if (index_to_canonical_name.find(idx) == index_to_canonical_name.end())
      index_to_canonical_name[idx] = name;
  }
  if (name_to_index.empty()) return;  // not a Cython 3.x file

  // Step 2: Find the length index array.
  static const std::regex re_index_arr(
      R"PYREGEX(const\s+struct\s*\{\s*const\s+unsigned\s+int\s+length\s*:\s*12\s*;\s*\}\s*index\s*\[\s*\]\s*=\s*\{)PYREGEX");
  std::smatch m_idx;
  if (!std::regex_search(csrc, m_idx, re_index_arr)) return;
  size_t arr_start = m_idx.position() + m_idx[0].length();
  size_t arr_end = csrc.find("};", arr_start);
  if (arr_end == std::string::npos) return;
  std::string arr_body = csrc.substr(arr_start, arr_end - arr_start);
  static const std::regex re_entry(R"PYREGEX(\{(\d+)\})PYREGEX");
  std::vector<int> lengths;
  auto eb = std::sregex_iterator(arr_body.begin(), arr_body.end(), re_entry);
  for (auto it = eb; it != end; ++it) {
    lengths.push_back(std::stoi((*it)[1].str()));
  }

  // Step 3: Find the bzip2 or zlib cstring and decompress.
  std::string decompressed;
  bool ok = false;
  // Try bzip2 first
  static const std::regex re_bz(
      R"PYREGEX(const char\*\s+const\s+cstring\s*=\s*"BZh9)PYREGEX");
  std::smatch m_bz;
  if (std::regex_search(csrc, m_bz, re_bz)) {
    size_t start = m_bz.position() + m_bz[0].length() - 4;
    size_t semi = find_cstring_statement_end(csrc, start, true);
    if (semi != std::string::npos) {
      std::string raw = extract_cstring_bytes(csrc, start, semi);
      ok = bzip2_decompress(raw, decompressed);
    }
  }
  // Try zlib
  if (!ok) {
    size_t pos = 0;
    while (true) {
      size_t p = csrc.find("const char* const cstring", pos);
      if (p == std::string::npos) break;
      size_t eq = csrc.find('=', p);
      if (eq == std::string::npos) break;
      size_t q = csrc.find('"', eq);
      if (q == std::string::npos) break;
      size_t start = q + 1;
      size_t semi = find_cstring_statement_end(csrc, start, true);
      if (semi == std::string::npos) { pos = q + 1; continue; }
      std::string raw = extract_cstring_bytes(csrc, start, semi);
      for (size_t ii = 0; ii < std::min((size_t)20, raw.size()); ++ii) {
        fprintf(stderr, "%02x ", (unsigned char)raw[ii]);
      }
      std::cerr << "\n";
      if (raw.size() >= 2 && (unsigned char)raw[0] == 0x78) {
        if (zlib_decompress(raw, decompressed)) {
          ok = true;
          break;
        }
      }
      pos = q + 1;
    }
  }
  if (!ok) return;

  // Step 4: Determine N_unicode and N_total.
  // We look for the pattern:
  //   for (int i = 0; i < N_unicode; i++) {
  //     ... PyUnicode_DecodeUTF8 ...
  //   }
  //   for (int i = N_unicode; i < N_total; i++) {
  //     ... PyBytes_FromStringAndSize ...
  //   }
  // We use simple string searches (not regex) for performance on large files.
  int n_unicode = 0, n_total = 0;
  {
    // Find PyUnicode_DecodeUTF8 and PyBytes_FromStringAndSize positions
    size_t pos_unicode = csrc.find("PyUnicode_DecodeUTF8");
    size_t pos_bytes = csrc.find("PyBytes_FromStringAndSize");
    if (pos_unicode != std::string::npos && pos_bytes != std::string::npos) {
      // Find the for loop containing PyUnicode_DecodeUTF8 — look for "i < N" before it
      // Search backwards from pos_unicode for "i < "
      size_t search_start = (pos_unicode > 200) ? pos_unicode - 200 : 0;
      std::string window = csrc.substr(search_start, pos_unicode - search_start);
      // Find "i < " in the window
      size_t p = window.rfind("i < ");
      if (p != std::string::npos) {
        // Parse the number after "i < "
        size_t q = p + 4;
        std::string num;
        while (q < window.size() && std::isdigit((unsigned char)window[q])) {
          num.push_back(window[q]); ++q;
        }
        if (!num.empty()) n_unicode = std::stoi(num);
      }
      // For N_total: search forwards from pos_bytes for "i < "
      // Actually look BEFORE pos_bytes for "i < N_total"
      size_t search_start2 = (pos_bytes > 200) ? pos_bytes - 200 : 0;
      std::string window2 = csrc.substr(search_start2, pos_bytes - search_start2);
      size_t p2 = window2.rfind("i < ");
      if (p2 != std::string::npos) {
        size_t q = p2 + 4;
        std::string num;
        while (q < window2.size() && std::isdigit((unsigned char)window2[q])) {
          num.push_back(window2[q]); ++q;
        }
        if (!num.empty()) n_total = std::stoi(num);
      }
    }
  }
  if (n_total == 0) {
    // Fallback: assume all are unicode
    n_total = (int)lengths.size();
    n_unicode = n_total;
  }
  if (n_total > (int)lengths.size()) n_total = (int)lengths.size();
  if (n_unicode > n_total) n_unicode = n_total;

  // Step 5: Slice decompressed bytes per index.
  size_t pos = 0;
  for (int i = 0; i < n_total && pos < decompressed.size(); ++i) {
    int len = lengths[i];
    if (pos + len > decompressed.size()) len = (int)(decompressed.size() - pos);
    std::string value = decompressed.substr(pos, len);
    pos += len;
    Sym s;
    s.name = index_to_canonical_name[i];
    s.str_val = value;
    if (i < n_unicode) {
      s.kind = SymKind::Unicode;
      s.py_expr = py_repr_long(value);
    } else {
      s.kind = SymKind::Bytes;
      s.py_expr = "b" + py_repr_long(value);
    }
    s.py_id = value;
    s.resolved = true;
    st.by_cname[s.name] = std::move(s);
  }

  // Step 6: Add aliases for each #define'd name.
  std::map<std::string, Sym> aliases;
  for (auto& kv : name_to_index) {
    const std::string& name = kv.first;
    int idx = kv.second;
    if (idx >= n_total) continue;
    auto it = st.by_cname.find(index_to_canonical_name[idx]);
    if (it == st.by_cname.end()) continue;
    if (name == it->first) continue;
    aliases[name] = it->second;
    aliases[name].name = name;
  }
  for (auto& kv : aliases) st.by_cname[kv.first] = std::move(kv.second);
}

// Parse Cython 3.x tuple declarations:
//   __pyx_mstate_global->__pyx_tuple[N] = PyTuple_Pack(K, ...);
static void parse_cython3_tuples(const std::string& csrc, SymbolTable& st) {
  static const std::regex re(
      R"PYREGEX(__pyx_tuple\[(\d+)\]\s*=\s*PyTuple_Pack\s*\(\s*\d+\s*,\s*([^;]+?)\)\s*;\s*if)PYREGEX");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string tname = "__pyx_tuple[" + (*it)[1].str() + "]";
    std::string args = (*it)[2].str();
    std::vector<std::string> parts;
    std::string cur;
    int depth = 0;
    for (char c : args) {
      if (c == '(') ++depth;
      if (c == ')') --depth;
      if (c == ',' && depth == 0) { parts.push_back(trim(cur)); cur.clear(); }
      else cur.push_back(c);
    }
    if (!cur.empty()) parts.push_back(trim(cur));
    for (auto& p : parts) {
      size_t arrow = p.find("->__pyx_");
      if (arrow != std::string::npos) p = "__pyx_" + p.substr(arrow + 7);
      static const std::regex re_cast(R"PYREGEX(\(\s*PyObject\s*\*\s*\)\s*)PYREGEX");
      p = std::regex_replace(p, re_cast, "");
      p = trim(p);
    }
    Sym s;
    s.name = tname;
    s.kind = SymKind::Tuple;
    s.elements = parts;
    s.resolved = true;
    st.by_cname[tname] = std::move(s);
  }
}

// Parse Cython 3.x slice declarations:
//   __pyx_mstate_global->__pyx_slice[N] = PySlice_New(START, STOP, STEP);
static void parse_cython3_slices(const std::string& csrc, SymbolTable& st) {
  static const std::regex re(
      R"PYREGEX(__pyx_slice\[(\d+)\]\s*=\s*PySlice_New\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+?)\))PYREGEX");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string sname = "__pyx_slice[" + (*it)[1].str() + "]";
    auto strip_state = [](std::string s) {
      s = trim(s);
      size_t arrow = s.find("->__pyx_");
      if (arrow != std::string::npos) s = "__pyx_" + s.substr(arrow + 7);
      return s;
    };
    Sym s;
    s.name = sname;
    s.kind = SymKind::Slice;
    s.elements = {strip_state((*it)[2].str()), strip_state((*it)[3].str()), strip_state((*it)[4].str())};
    s.resolved = true;
    st.by_cname[sname] = std::move(s);
  }
}

// Parse Cython 3.x int declarations:
//   __pyx_mstate_global->__pyx_int[N] = PyLong_FromLong(N);
static void parse_cython3_ints(const std::string& csrc, SymbolTable& st) {
  static const std::regex re(
      R"PYREGEX(__pyx_int\[(\d+)\]\s*=\s*Py(?:Long|Int)_FromLong\s*\(\s*(-?\d+)\s*\))PYREGEX");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    std::string name = "__pyx_int[" + (*it)[1].str() + "]";
    long long val = std::stoll((*it)[2].str());
    Sym s;
    s.name = name;
    s.kind = SymKind::Int;
    s.int_val = val;
    s.py_expr = std::to_string(val);
    s.resolved = true;
    st.by_cname[name] = std::move(s);
  }
}


// ---------------------------------------------------------------------------
//  Stage 3: Function definition extractor
// ---------------------------------------------------------------------------

struct FuncDef {
  std::string c_pf_name;
  std::string py_name;
  std::vector<std::string> args;
  std::vector<std::string> body_lines;
  std::vector<std::string> py_body;
  int firstlineno = 0;
};

static std::vector<FuncDef> extract_functions(const std::string& csrc,
                                              const SymbolTable& st) {
  (void)st;
  std::vector<FuncDef> out;
  static const std::regex re_pf(
      R"(static\s+PyObject\s*\*\s*(__pyx_pf_[A-Za-z0-9_]+)\s*\(([^)]*)\)\s*\{)");
  auto begin = std::sregex_iterator(csrc.begin(), csrc.end(), re_pf);
  auto end = std::sregex_iterator();
  for (auto it = begin; it != end; ++it) {
    FuncDef f;
    f.c_pf_name = (*it)[1].str();
    std::string params = (*it)[2].str();
    size_t lbrace = (size_t)(*it).position() + (*it)[0].length() - 1;
    int depth = 1;
    size_t i = lbrace + 1;
    while (i < csrc.size() && depth > 0) {
      char c = csrc[i];
      if (c == '{') ++depth;
      else if (c == '}') --depth;
      if (c == '"') {
        std::string dummy;
        size_t ep;
        if (parse_c_string_literal(csrc, i, dummy, ep)) { i = ep; continue; }
      }
      ++i;
    }
    std::string body = csrc.substr(lbrace + 1, i - lbrace - 2);
    f.body_lines.push_back(body);

    std::vector<std::string> arg_parts;
    std::string cur;
    int d = 0;
    for (char c : params) {
      if (c == '(') ++d;
      if (c == ')') --d;
      if (c == ',' && d == 0) { arg_parts.push_back(trim(cur)); cur.clear(); }
      else cur.push_back(c);
    }
    if (!cur.empty()) arg_parts.push_back(trim(cur));

    for (auto& a : arg_parts) {
      static const std::regex re_arg(R"(\*?\s*(__pyx_[A-Za-z0-9_]+)\s*$)");
      std::smatch m;
      if (std::regex_search(a, m, re_arg)) {
        std::string cname = m[1].str();
        if (cname == "__pyx_self") continue;
        if (starts_with(cname, "__pyx_v_")) {
          std::string py = cname.substr(8);
          f.args.push_back(py);
        }
      }
    }

    // Look up the python function name from the mdef entry, by matching
    // __pyx_pw_<middle>_N_ against __pyx_pf_<middle>__
    // Cython 0.x: static PyMethodDef __pyx_mdef_X = {...};
    // Cython 3.x: static PyMethodDef __pyx_mdef_X = {...}; (same)
    //              OR static PyMethodDef __pyx_Umdef_X = {...}; (with 'U' prefix for some)
    static const std::regex re_mdef(
        R"PYREGEX(static\s+PyMethodDef\s+(__pyx_[Um]*mdef_[A-Za-z0-9_]+)\s*=\s*\{\s*"([^"]+)"\s*,\s*\(?\s*PyCFunction\s*\)?\s*(__pyx_pw_[A-Za-z0-9_]+)\s*,\s*(\w+)\s*,\s*0\s*\}\s*;)PYREGEX");
    std::string pf_prefix = f.c_pf_name;
    auto mbegin = std::sregex_iterator(csrc.begin(), csrc.end(), re_mdef);
    auto mend = std::sregex_iterator();
    for (auto mit = mbegin; mit != mend; ++mit) {
      std::string pw = (*mit)[3].str();
      std::string middle_pw = pw.substr(8);
      std::string middle_pf = pf_prefix.substr(8);
      size_t last_us = middle_pw.rfind('_');
      if (last_us != std::string::npos && last_us > 0) {
        size_t prev_us = middle_pw.rfind('_', last_us - 1);
        if (prev_us != std::string::npos) {
          std::string stripped = middle_pw.substr(0, prev_us);
          std::string pf_strip = middle_pf;
          while (!pf_strip.empty() && pf_strip.back() == '_') pf_strip.pop_back();
          if (stripped == pf_strip) { f.py_name = (*mit)[2].str(); break; }
        }
      }
    }
    if (f.py_name.empty()) {
      static const std::regex re_ctx(R"PYREGEX(__Pyx_RefNannySetupContext\(\s*"([^"]+)"\s*,)PYREGEX");
      std::smatch mc;
      if (std::regex_search(body, mc, re_ctx)) f.py_name = mc[1].str();
      else f.py_name = "<unknown>";
    }
    out.push_back(std::move(f));
  }
  return out;
}

// ---------------------------------------------------------------------------
//  Stage 4: Body decoder (DEEP-REGEX symbolic execution)
// ---------------------------------------------------------------------------

struct DecodeCtx {
  std::map<std::string, std::string> ssa;
  std::map<std::string, std::string> varmap;
  std::map<std::string, std::string> globals;
  std::vector<std::string> out;
  const SymbolTable& st;
  const FuncDef* func = nullptr;
  std::vector<std::string>* debug = nullptr;
  std::string indent = "";
  bool is_function = true;
  explicit DecodeCtx(const SymbolTable& s) : st(s) {}
};

static std::string resolve_ref(const std::string& tok, DecodeCtx& ctx);
static std::string decode_rhs(const std::string& rhs, DecodeCtx& ctx);

struct StmtResult {
  bool matched = false;
  std::string py_stmt;
  bool is_block_end = false;
  bool is_block_start = false;
  std::string block_keyword;
  std::string block_cond;
  std::string indent_delta;
};

static std::vector<std::string> split_statements(const std::string& body) {
  std::vector<std::string> out;
  std::string cur;
  int depth = 0;
  for (size_t i = 0; i < body.size(); ++i) {
    char c = body[i];
    if (c == '"') {
      std::string dummy;
      size_t ep;
      if (parse_c_string_literal(body, i, dummy, ep)) {
        cur += body.substr(i, ep - i);
        i = ep - 1;
        continue;
      }
    }
    if (c == '(') ++depth;
    else if (c == ')') --depth;
    if (c == ';' && depth == 0) {
      std::string s = trim(cur);
      if (!s.empty()) out.push_back(s);
      cur.clear();
    } else cur.push_back(c);
  }
  std::string s = trim(cur);
  if (!s.empty()) out.push_back(s);
  return out;
}

static std::string resolve_ref(const std::string& tok, DecodeCtx& ctx) {
  std::string t = trim(tok);
  static const std::regex re_cast(R"(\(\s*PyObject\s*\*\s*\)\s*([A-Za-z0-9_]+))");
  std::smatch mc;
  while (std::regex_search(t, mc, re_cast)) t = mc[1].str();

  // Strip __pyx_mstate_global->__pyx_X -> __pyx_X (Cython 3.x module state pattern)
  // Also handle __pyx_mstate->__pyx_X
  if (starts_with(t, "__pyx_mstate_global->__pyx_")) {
    t = "__pyx_" + t.substr(27);  // len("__pyx_mstate_global->__pyx_") = 27
  } else if (starts_with(t, "__pyx_mstate->__pyx_")) {
    t = "__pyx_" + t.substr(20);  // len("__pyx_mstate->__pyx_") = 20
  }

  if (starts_with(t, "__pyx_t_")) {
    auto it = ctx.ssa.find(t);
    if (it != ctx.ssa.end()) return it->second;
    return t;
  }
  if (starts_with(t, "__pyx_v_")) {
    auto it = ctx.varmap.find(t);
    if (it != ctx.varmap.end()) return it->second;
    return t.substr(8);
  }
  if (t == "__pyx_d" || t == "__pyx_mstate_global->__pyx_d" || t == "__pyx_mstate->__pyx_d")
    return "globals()";
  if (t == "__pyx_m" || t == "__pyx_mstate_global->__pyx_m") return "<module>";
  if (t == "__pyx_b" || t == "__pyx_mstate_global->__pyx_b") return "builtins";
  if (starts_with(t, "__pyx_builtin_")) {
    std::string name = t.substr(14);  // length of "__pyx_builtin_"
    return name;
  }
  auto it = ctx.st.by_cname.find(t);
  if (it != ctx.st.by_cname.end()) {
    const Sym& s = it->second;
    if (s.resolved) {
      if (s.kind == SymKind::Tuple) {
        std::string out = "(";
        for (size_t i = 0; i < s.elements.size(); ++i) {
          if (i) out += ", ";
          out += resolve_ref(s.elements[i], ctx);
        }
        if (s.elements.size() == 1) out += ",";
        out += ")";
        return out;
      }
      if (s.kind == SymKind::Slice) {
        std::string start = resolve_ref(s.elements[0], ctx);
        std::string stop = resolve_ref(s.elements[1], ctx);
        std::string step = resolve_ref(s.elements[2], ctx);
        auto norm = [](const std::string& x) {
          if (x == "Py_None" || x == "None") return std::string();
          return x;
        };
        return "[" + norm(start) + ":" + norm(stop) + ":" + norm(step) + "]";
      }
      if (s.kind == SymKind::Int) return std::to_string(s.int_val);
      return s.py_expr;
    }
  }
  if (t == "Py_None" || t == "__pyx_k_None" || t == "None") return "None";
  if (t == "Py_True" || t == "True") return "True";
  if (t == "Py_False" || t == "False") return "False";
  if (t == "__pyx_empty_tuple") return "()";
  if (t == "__pyx_empty_bytes") return "b\"\"";
  if (t == "__pyx_empty_unicode") return "\"\"";
  static const std::regex re_intlit(R"(^-?\d+$)");
  if (std::regex_match(t, re_intlit)) return t;
  if (t == "NULL" || t == "0") return "None";
  return t;
}

static std::string decode_rhs(const std::string& rhs, DecodeCtx& ctx) {
  std::string r = trim(rhs);
  static const std::regex re_cast(R"(\(\s*PyObject\s*\*\s*\))");
  r = std::regex_replace(r, re_cast, "");

  std::smatch m;

  // Cython 3.x: __Pyx_PyObject_FastCall(FN, args, nargs) — vectorcall
  // Pattern: __Pyx_PyObject_FastCall((PyObject*)__pyx_t_22, __pyx_callargs+__pyx_t_5, (2-__pyx_t_5) | (...))
  // We approximate: FN(*callargs) — but we don't know callargs contents, so emit FN(*args)
  static const std::regex re_fastcall(
      R"(__Pyx_PyObject_FastCall\s*\(\s*\(?\s*PyObject\s*\*\s*\)?\s*([^,]+?)\s*,\s*[^,]+,\s*[^)]+\))");
  if (std::regex_search(r, m, re_fastcall)) {
    return resolve_ref(m[1].str(), ctx) + "(*callargs)";
  }
  // Cython 3.x: PyObject_RichCompare(A, B, Py_EQ/Py_NE/Py_LT/Py_LE/Py_GT/Py_GE)
  static const std::regex re_richcmp(
      R"PYREGEX(PyObject_RichCompare\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*Py_(EQ|NE|LT|LE|GT|GE)\))PYREGEX");
  if (std::regex_search(r, m, re_richcmp)) {
    std::string op = "==";
    if (m[3].str() == "NE") op = "!=";
    else if (m[3].str() == "LT") op = "<";
    else if (m[3].str() == "LE") op = "<=";
    else if (m[3].str() == "GT") op = ">";
    else if (m[3].str() == "GE") op = ">=";
    return resolve_ref(m[1].str(), ctx) + " " + op + " " + resolve_ref(m[2].str(), ctx);
  }
  // Cython 3.x: __Pyx_PyNumber_Add/Subtract/Multiply/etc (binary ops)
  static const std::regex re_binop(
      R"PYREGEX(__Pyx_PyNumber_(Add|Subtract|Multiply|Divide|Remainder|And|Or|Xor|Lshift|Rshift)\s*\(\s*([^,]+)\s*,\s*([^)]+?)\))PYREGEX");
  if (std::regex_search(r, m, re_binop)) {
    std::string op = "+";
    if (m[1].str() == "Subtract") op = "-";
    else if (m[1].str() == "Multiply") op = "*";
    else if (m[1].str() == "Divide") op = "/";
    else if (m[1].str() == "Remainder") op = "%";
    else if (m[1].str() == "And") op = "&";
    else if (m[1].str() == "Or") op = "|";
    else if (m[1].str() == "Xor") op = "^";
    else if (m[1].str() == "Lshift") op = "<<";
    else if (m[1].str() == "Rshift") op = ">>";
    return resolve_ref(m[2].str(), ctx) + " " + op + " " + resolve_ref(m[3].str(), ctx);
  }
  // Cython 3.x: PyUnicode_Join(sep, iterable) -> sep.join(iterable)
  static const std::regex re_unicodejoin(
      R"(PyUnicode_Join\s*\(\s*([^,]+)\s*,\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_unicodejoin)) {
    return resolve_ref(m[1].str(), ctx) + ".join(" + resolve_ref(m[2].str(), ctx) + ")";
  }
  // Cython 3.x: PyUnicode_Split(s, sep, maxsplit) -> s.split(sep, maxsplit)
  static const std::regex re_unicodesplit(
      R"PYREGEX(PyUnicode_Split\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+?)\))PYREGEX");
  if (std::regex_search(r, m, re_unicodesplit)) {
    std::string sep = resolve_ref(m[2].str(), ctx);
    std::string maxsp = resolve_ref(m[3].str(), ctx);
    if (sep == "-1" || sep == "Py_None" || sep == "None") {
      return resolve_ref(m[1].str(), ctx) + ".split()";
    }
    if (maxsp == "-1") {
      return resolve_ref(m[1].str(), ctx) + ".split(" + sep + ")";
    }
    return resolve_ref(m[1].str(), ctx) + ".split(" + sep + ", " + maxsp + ")";
  }
  // Cython 3.x: __Pyx_GetItemInt_List(seq, idx, ...) -> seq[idx]
  static const std::regex re_getitemint(
      R"(__Pyx_GetItemInt_(?:List|Tuple|Sequence)\s*\(\s*([^,]+)\s*,\s*([^,]+))");
  if (std::regex_search(r, m, re_getitemint)) {
    return resolve_ref(m[1].str(), ctx) + "[" + resolve_ref(m[2].str(), ctx) + "]";
  }
  // Cython 3.x: __Pyx_PyNumber_Int(x) -> int(x)
  static const std::regex re_numint(
      R"(__Pyx_PyNumber_Int\s*\(\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_numint)) {
    return "int(" + resolve_ref(m[1].str(), ctx) + ")";
  }
  // Cython 3.x: PyList_New(N) -> [] (empty list)
  static const std::regex re_listnew(
      R"(PyList_New\s*\(\s*\d+\s*\))");
  if (std::regex_search(r, m, re_listnew)) return "[]";
  // Cython 3.x: __Pyx_PyDict_NewPresized(N) or PyDict_New()
  static const std::regex re_dictnew(
      R"(__Pyx_PyDict_NewPresized\s*\(\s*\d+\s*\))");
  if (std::regex_search(r, m, re_dictnew)) return "{}";
  static const std::regex re_dictnew2(R"(PyDict_New\s*\(\s*\))");
  if (std::regex_search(r, m, re_dictnew2)) return "{}";
  // Cython 3.x: PyUnicode_FromStringAndSize / PyUnicode_FromString -> the string
  // These are usually used with literal strings; skip.
  // Cython 3.x: __Pyx_PyObject_GetAttrStr
  // (already handled below in the original patterns)

  // 1) __Pyx_PyObject_Call(FN, ARGS, KWDS)
  static const std::regex re_call(R"(__Pyx_PyObject_Call\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_call)) {
    std::string fn = resolve_ref(m[1].str(), ctx);
    std::string args_tok = trim(m[2].str());
    std::string kwds_tok = trim(m[3].str());
    std::string args;
    if (args_tok == "NULL" || args_tok == "0" || args_tok == "__pyx_empty_tuple" ||
        args_tok == "__pyx_mstate_global->__pyx_empty_tuple") {
      args = "";
    } else {
      args = resolve_ref(args_tok, ctx);
      // Strip outer parens of a tuple: ("a", "b") -> "a", "b"
      if (!args.empty() && args.front() == '(' && args.back() == ')')
        args = args.substr(1, args.size() - 2);
      // Strip trailing comma from single-element tuple: ("a",) -> "a"
      if (!args.empty() && args.back() == ',') args.pop_back();
      args = trim(args);
    }
    if (kwds_tok != "NULL" && kwds_tok != "0") {
      return fn + "(" + args + ", **" + resolve_ref(kwds_tok, ctx) + ")";
    }
    return fn + "(" + args + ")";
  }
  // 2) __Pyx_PyObject_CallOneArg(FN, ARG)
  static const std::regex re_call1(R"(__Pyx_PyObject_CallOneArg\s*\(\s*([^,]+)\s*,\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_call1)) {
    return resolve_ref(m[1].str(), ctx) + "(" + resolve_ref(m[2].str(), ctx) + ")";
  }
  // 3) __Pyx_PyObject_Call2Args(FN, A1, A2)
  static const std::regex re_call2(R"(__Pyx_PyObject_Call2Args\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_call2)) {
    return resolve_ref(m[1].str(), ctx) + "(" + resolve_ref(m[2].str(), ctx) + ", " +
           resolve_ref(m[3].str(), ctx) + ")";
  }
  // 4) __Pyx_PyObject_CallNoArg(FN)
  static const std::regex re_call0(R"(__Pyx_PyObject_CallNoArg\s*\(\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_call0)) {
    return resolve_ref(m[1].str(), ctx) + "()";
  }
  // 5) __Pyx_PyObject_GetAttrStr(OBJ, NAME)
  static const std::regex re_getattr(R"(__Pyx_PyObject_GetAttrStr\s*\(\s*([^,]+)\s*,\s*(__pyx_[^)]+?)\))");
  if (std::regex_search(r, m, re_getattr)) {
    std::string obj = resolve_ref(m[1].str(), ctx);
    std::string attr = resolve_ref(m[2].str(), ctx);
    if (attr.size() >= 2 && attr.front() == '"' && attr.back() == '"')
      attr = attr.substr(1, attr.size() - 2);
    else if (attr.size() >= 3 && attr.substr(0, 2) == "b\"" && attr.back() == '"')
      attr = attr.substr(2, attr.size() - 3);
    return obj + "." + attr;
  }
  // 6) __Pyx_PyObject_GetItem(OBJ, KEY)
  static const std::regex re_getitem(R"(__Pyx_PyObject_GetItem\s*\(\s*([^,]+)\s*,\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_getitem)) {
    std::string obj = resolve_ref(m[1].str(), ctx);
    std::string key = resolve_ref(m[2].str(), ctx);
    // If the key is a slice (already wrapped in [...]), use it directly as
    // the subscript instead of wrapping again.
    if (!key.empty() && key.front() == '[' && key.back() == ']') {
      return obj + key;
    }
    return obj + "[" + key + "]";
  }
  // 7) PySlice_New(START, STOP, STEP)
  static const std::regex re_slice(R"(PySlice_New\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_slice)) {
    auto norm = [&](const std::string& x) {
      std::string v = resolve_ref(x, ctx);
      if (v == "Py_None" || v == "None") return std::string();
      return v;
    };
    return "[" + norm(m[1].str()) + ":" + norm(m[2].str()) + ":" + norm(m[3].str()) + "]";
  }
  // 8) PyTuple_Pack(N, A, B, ...)
  static const std::regex re_pack(R"(PyTuple_Pack\s*\(\s*\d+\s*,\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_pack)) {
    std::string args = m[1].str();
    std::vector<std::string> parts;
    std::string cur;
    int depth = 0;
    for (char c : args) {
      if (c == '(') ++depth;
      else if (c == ')') --depth;
      if (c == ',' && depth == 0) { parts.push_back(trim(cur)); cur.clear(); }
      else cur.push_back(c);
    }
    if (!cur.empty()) parts.push_back(trim(cur));
    std::string out = "(";
    for (size_t i = 0; i < parts.size(); ++i) {
      if (i) out += ", ";
      out += resolve_ref(parts[i], ctx);
    }
    if (parts.size() == 1) out += ",";
    out += ")";
    return out;
  }
  // 9) __Pyx_PyDict_NewPresized(N)  or  PyDict_New()
  static const std::regex re_dictn(R"(__Pyx_PyDict_NewPresized\s*\(\s*\d+\s*\))");
  if (std::regex_search(r, m, re_dictn)) return "{}";
  static const std::regex re_dict(R"(PyDict_New\s*\(\s*\))");
  if (std::regex_search(r, m, re_dict)) return "{}";
  // 10) __Pyx_PyExecGlobals(CODE)
  static const std::regex re_exec(R"(__Pyx_PyExecGlobals\s*\(\s*([^)]+?)\))");
  if (std::regex_search(r, m, re_exec)) {
    return "exec(" + resolve_ref(m[1].str(), ctx) + ")";
  }
  // 11) __Pyx_GetModuleGlobalName(TMP, NAME)
  static const std::regex re_global(R"(__Pyx_GetModuleGlobalName\s*\(\s*[^,]+\s*,\s*(__pyx_[^)]+?)\))");
  if (std::regex_search(r, m, re_global)) {
    std::string v = resolve_ref(m[1].str(), ctx);
    if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
      v = v.substr(1, v.size() - 2);
    return v;
  }
  // 12) __Pyx_PyCode_New(...)
  static const std::regex re_codenew(R"(__Pyx_PyCode_New\s*\([^)]*\))");
  if (std::regex_search(r, m, re_codenew)) return "<code object>";
  // Fallback: single reference
  return resolve_ref(r, ctx);
}

static bool try_decode_stmt(const std::string& stmt, DecodeCtx& ctx,
                            StmtResult& res) {
  res.matched = false;
  std::string s = trim(stmt);

  // Skip noise: declarations, refnanny calls, error-handling, control-flow
  // NOTE: The regex below ends with an extra ")" -- that ")" is required
  // because the raw-string terminator is ")PYREGEX"" and we need the regex
  // itself to end with ")" (the alternation-group close).  The extra ")" is
  // consumed by the terminator; the regex content is "^(...|return\s+__pyx_m)".
  static const std::regex re_skip(
      R"PYREGEX(^(PyObject\s*\*|int\s+|const\s+char\s*\*|CYTHON_UNUSED\s+.*|__Pyx_RefNannyDeclarations|__Pyx_RefNannySetupContext|__Pyx_RefNannyFinishContext|__Pyx_AddTraceback|__Pyx_GOTREF|__Pyx_GIVEREF|__Pyx_DECREF|__Pyx_INCREF|__Pyx_XGIVEREF|__Pyx_XGOTREF|__Pyx_XDECREF|__Pyx_INCREF|__Pyx_DECREF|Py_INCREF|Py_DECREF|Py_XINCREF|Py_XDECREF|Py_CLEAR|return\s+__pyx_r|return\s+__pyx_m|return\s+0|return\s+-1|goto\s+__pyx_L|if\s*\(\s*unlikely|if\s*\(\s*likely|if\s*\(\s*CYTHON_UNPACK_METHODS|if\s*\(\s*Py|if\s*\(\s*__pyx_m|if\s*\(\s*__Pyx|if\s*\(__pyx|__pyx_lineno|__pyx_clineno|__pyx_filename|__pyx_L\d+_error\s*:|__pyx_L\d+\s*:|__pyx_L\d+_error|__pyx_L\d+:\s*$|\{|\}|/\*.*\*/|__Pyx_check_binary_version|__Pyx_InitGlobals|__Pyx_InitCachedBuiltins|__Pyx_InitCachedConstants|__Pyx_init_sys_getdefaultencoding_params|__Pyx_patch_abc|__Pyx_modinit_\w+_code|__Pyx_pymod_create|__Pyx_copy_spec_to_module|__Pyx_PyFrame_Initialize_Offsets|__Pxy_PyFrame_Initialize_Offsets|PyModule_Create|PyModule_NewObject|PyModule_GetDict|PyImport_AddModule|PyImport_ImportModule|PyImport_GetModuleDict|PyDict_GetItemString|PyDict_SetItemString|PyTuple_New|PyBytes_FromStringAndSize|PyUnicode_FromStringAndSize|PyLong_FromLong|PyInt_FromLong|PyEval_InitThreads|PyErr_SetString|PyErr_Occurred|PyErr_Restore|Py_FatalError|PyMethod_Check|PyMethod_GET_SELF|PyMethod_GET_FUNCTION|PyObject_GetAttrString|PyObject_GetAttr|__Pyx_INCREF|__Pyx_DECREF_SET|__Pyx_PyCode_New|__Pyx_CyFunction_New|__Pyx_CyFunction_init|__Pyx_FusedFunction_init|__Pyx_Coroutine_init|__Pyx_Generator_init|__Pyx_AsyncGen_init|__Pyx_StopAsyncIteration_init|__Pyx_GetBuiltinName|__Pyx_NewRef|__Pyx_PyMODINIT_FUNC|__pyx_m\s*=\s*__pyx_pyinit_module|__pyx_m\s*=\s*Py_InitModule4|__pyx_m\s*=\s*PyModule_Create|__pyx_d\s*=|__pyx_b\s*=|__pyx_cython_runtime\s*=|__pyx_empty_tuple\s*=|__pyx_empty_bytes\s*=|__pyx_empty_unicode\s*=|__pyx_t_\d+\s*=\s*NULL|__pyx_v_\w+\s*=|__Pyx_PyErr_GivenExceptionMatches|__Pyx_PyException_Check|__Pyx_UnpackMethod|__Pyx_PyFastFunction_Check|__Pyx_PyCFunctionFast|__Pyx_PyCFunctionFastWithKeywords|PyObject_SetAttr|PyObject_SetAttrString|__Pyx_PyCode_NewEmpty|__Pyx_PyBytes_Contains|__Pyx_PyObject_Call\s*\(|__Pyx_PyObject_CallOneArg\s*\(|__Pyx_PyObject_Call2Args\s*\(|__Pyx_PyObject_CallNoArg\s*\(|__Pyx_PyObject_GetAttrStr\s*\(|__Pyx_PyObject_GetItem\s*\(|__Pyx_PyExecGlobals\s*\(|__Pyx_PyDict_NewPresized\s*\(|PyDict_New\s*\(|PySlice_New\s*\(|PyTuple_Pack\s*\())PYREGEX");
  if (std::regex_search(s, re_skip)) {
    res.matched = true;
    return true;
  }
  // Skip plain labels like "__pyx_L1_error:;" or "__pyx_L0:;"
  if (std::regex_match(s, std::regex(R"(__pyx_L\d+\w*:?\s*;?)"))) {
    res.matched = true;
    return true;
  }
  // Skip "return __pyx_r;" handled by skip; but also "return __pyx_m;" etc.
  if (starts_with(s, "return ")) {
    res.matched = true;
    return true;
  }

  // Pre-simplify ternary expressions around __Pyx_PyObject_Call*.
  // Pattern: (__pyx_t_N) ? Call2Args(FN, SELF, ARG) : CallOneArg(FN, ARG)
  // In Cython this is the "method unpack" optimization: if FN is a bound
  // method, extract SELF and call FN(SELF, ARG); otherwise call FN(ARG).
  // For decompilation we prefer the simpler form FN(ARG) -- the CallOneArg
  // branch -- because the bound-method case only differs in calling
  // convention, not in semantics (the result is the same).
  {
    static const std::regex re_tern(
        R"PYREGEX(\(\s*__pyx_t_\d+\s*\)\s*\?\s*__Pyx_PyObject_Call2Args\s*\([^)]+?\)\s*:\s*(__Pyx_PyObject_CallOneArg\s*\([^)]+?\)))PYREGEX");
    s = std::regex_replace(s, re_tern, "$1");
  }

  // __Pyx_CyFunction_New(&__pyx_mdef_X, ...)  -- mark temp as a function def.
  // Checked BEFORE re_assign because re_assign would otherwise consume this
  // and call decode_rhs, which doesn't know how to render a CyFunction_New call.
  // Note: re_cyfn doesn't consume the full statement (the call has more args
  // after __pyx_mdef_X), so we use regex_search.
  // Cython 0.x uses __pyx_mdef_X, Cython 3.x may use __pyx_mdef_X or __pyx_Umdef_X.
  {
    static const std::regex re_cyfn(
        R"PYREGEX(^(__pyx_t_\d+)\s*=\s*__Pyx_CyFunction_New\s*\(\s*&\s*(__pyx_[Um]*mdef_[A-Za-z0-9_]+)\s*,)PYREGEX");
    std::smatch m_cy;
    if (std::regex_search(s, m_cy, re_cyfn)) {
      std::string tmp = m_cy[1].str();
      std::string mdef = m_cy[2].str();
      ctx.ssa[tmp] = "__CYFUNCTION__:" + mdef;
      res.matched = true;
      return true;
    }
  }

  // __Pyx_PyExecGlobals(CODE) -- emit `exec(CODE)` as a statement.
  // Must be checked BEFORE re_assign so we can emit the statement, otherwise
  // re_assign would just store it in ssa without emitting.
  {
    static const std::regex re_exec(
        R"(^(__pyx_t_\d+|__pyx_r)\s*=\s*__Pyx_PyExecGlobals\s*\(\s*([^)]+?)\)\s*$)");
    std::smatch m_ex;
    if (std::regex_match(s, m_ex, re_exec)) {
      std::string code = resolve_ref(m_ex[2].str(), ctx);
      res.py_stmt = "exec(" + code + ")";
      res.matched = true;
      return true;
    }
  }

  // __pyx_t_N = 0  (clear temp) -- skip BEFORE re_assign so re_assign doesn't
  // store the literal `0` in ssa (which would shadow the real expression).
  {
    static const std::regex re_zero(R"(^(__pyx_t_\d+|__pyx_r)\s*=\s*0\s*$)");
    std::smatch m_z;
    if (std::regex_match(s, m_z, re_zero)) {
      res.matched = true;
      return true;
    }
  }

  // __pyx_t_N = NULL  (clear temp) -- also skip.
  {
    static const std::regex re_null(R"(^(__pyx_t_\d+|__pyx_r)\s*=\s*NULL\s*$)");
    std::smatch m_n;
    if (std::regex_match(s, m_n, re_null)) {
      res.matched = true;
      return true;
    }
  }

  static const std::regex re_assign(R"(^(__pyx_t_\d+|__pyx_r)\s*=\s*(.+)$)");
  std::smatch m;
  if (std::regex_match(s, m, re_assign)) {
    std::string lhs = m[1].str();
    std::string rhs = m[2].str();
    static const std::regex re_chk(R"(\s*if\s*\(\s*unlikely\s*\([^)]+\)\s*\)\s*__PYX_ERR\([^)]+\).*$)");
    rhs = std::regex_replace(rhs, re_chk, "");
    static const std::regex re_chk2(R"(\s*if\s*\(\s*unlikely\s*\(\s*!\s*__pyx_t_\d+\s*\)\s*\)\s*__PYX_ERR\([^)]+\).*$)");
    rhs = std::regex_replace(rhs, re_chk2, "");
    rhs = trim(rhs);

    if (lhs == "__pyx_r") {
      // __pyx_r = <expr>  -- this is a return statement inside a function.
      // Skip the error-path return: `__pyx_r = NULL` (or `__pyx_r = 0`).
      if (rhs == "NULL" || rhs == "0") {
        res.matched = true;
        return true;
      }
      std::string expr = decode_rhs(rhs, ctx);
      ctx.ssa["__pyx_r"] = expr;
      if (ctx.is_function) {
        res.py_stmt = "return " + expr;
      }
      res.matched = true;
      return true;
    }
    std::string expr = decode_rhs(rhs, ctx);
    ctx.ssa[lhs] = expr;
    res.matched = true;
    return true;
  }

  // __Pyx_GetModuleGlobalName(TMP, NAME) -> TMP = NAME (global lookup)
  // Cython 0.x: __Pyx_GetModuleGlobalName(__pyx_t_1, __pyx_n_s_NAME)
  // Cython 3.x: __Pyx_GetModuleGlobalName(__pyx_t_1, __pyx_mstate_global->__pyx_n_u_NAME)
  static const std::regex re_getglobal(
      R"PYREGEX(^__Pyx_GetModuleGlobalName\s*\(\s*(__pyx_t_\d+)\s*,\s*((?:__pyx_mstate(?:_global)?->__pyx_)?__pyx_[^)]+?)\))PYREGEX");
  if (std::regex_search(s, m, re_getglobal)) {
    std::string tmp = m[1].str();
    std::string name = resolve_ref(m[2].str(), ctx);
    if (name.size() >= 2 && name.front() == '"' && name.back() == '"')
      name = name.substr(1, name.size() - 2);
    else if (name.size() >= 3 && name.substr(0, 2) == "b\"" && name.back() == '"')
      name = name.substr(2, name.size() - 3);
    ctx.ssa[tmp] = name;
    res.matched = true;
    return true;
  }

  // __pyx_r = __pyx_t_N;  -> return <expr>   (alternative form)
  static const std::regex re_ret(R"(^__pyx_r\s*=\s*(__pyx_t_\d+)\s*$)");
  if (std::regex_match(s, m, re_ret)) {
    std::string t = m[1].str();
    auto it = ctx.ssa.find(t);
    if (it != ctx.ssa.end() && ctx.is_function) {
      res.py_stmt = "return " + it->second;
      res.matched = true;
      return true;
    }
    res.matched = true;
    return true;
  }

  // __pyx_t_N = 0;  (clear)
  static const std::regex re_zero(R"(^(__pyx_t_\d+|__pyx_r)\s*=\s*0\s*$)");
  if (std::regex_match(s, m, re_zero)) {
    res.matched = true;
    return true;
  }

  // PyDict_SetItem(__pyx_d, __pyx_n_s_NAME, VALUE);
  // or PyDict_SetItem(__pyx_mstate_global->__pyx_d, __pyx_mstate_global->__pyx_n_s_NAME, VALUE);
  // (Cython 3.x)
  static const std::regex re_modassign(
      R"PYREGEX(^PyDict_SetItem\s*\(\s*(?:__pyx_mstate(?:_global)?->__pyx_d|__pyx_d)\s*,\s*([^,]+?)\s*,\s*([^)]+?)\)\s*$)PYREGEX");
  if (std::regex_match(s, m, re_modassign)) {
    if (!ctx.is_function) {
      std::string name = resolve_ref(m[1].str(), ctx);
      if (name.size() >= 2 && name.front() == '"' && name.back() == '"')
        name = name.substr(1, name.size() - 2);
      else if (name.size() >= 3 && name.substr(0, 2) == "b\"" && name.back() == '"')
        name = name.substr(2, name.size() - 3);
      std::string val_tok = trim(m[2].str());
      std::string val = decode_rhs(val_tok, ctx);
      auto it = ctx.ssa.find(val_tok);
      if (it != ctx.ssa.end() && starts_with(it->second, "__CYFUNCTION__:")) {
        // Function definition: emit marker so post-processing can replace
        // with the actual `def NAME(args): ...` block.
        res.py_stmt = name + " = " + it->second;
        res.matched = true;
        return true;
      }
      res.py_stmt = name + " = " + val;
      res.matched = true;
      return true;
    }
    res.matched = true;
    return true;
  }

  static const std::regex re_dictset(
      R"(^PyDict_SetItem\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+?)\)\s*$)");
  if (std::regex_match(s, m, re_dictset)) {
    res.matched = true;
    return true;
  }

  static const std::regex re_setattr(
      R"(^PyObject_SetAttr(?:String)?\s*\(\s*__pyx_m\s*,\s*[^,]+,\s*([^)]+?)\)\s*$)");
  if (std::regex_match(s, m, re_setattr)) {
    res.matched = true;
    return true;
  }

  // __Pyx_PyExecGlobals(CODE) - emit exec()
  static const std::regex re_exec(
      R"((__pyx_t_\d+)\s*=\s*__Pyx_PyExecGlobals\s*\(\s*([^)]+?)\)\s*$)");
  if (std::regex_match(s, m, re_exec)) {
    std::string code = resolve_ref(m[2].str(), ctx);
    res.py_stmt = "exec(" + code + ")";
    res.matched = true;
    return true;
  }

  // (Note: re_cyfn is checked earlier, before re_assign, so that
  //  `__pyx_t_N = __Pyx_CyFunction_New(...)` is recognized as a function-def
  //  marker instead of being consumed by re_assign + decode_rhs.)

  return false;
}

// Preprocess a function/module body before splitting into statements:
//   - remove C comments  /* ... */ and // ...
//   - remove preprocessor lines  #if/#else/#endif/#ifdef/#ifndef/#define/#undef
//   - remove label lines like "__pyx_L0:;" or "__pyx_L1_error:;"
//   - remove standalone `{` and `}` (block braces) since split_statements
//     only tracks parens, not braces
//   - unwrap `if (CALL(...) < 0) __PYX_ERR(...)` into just `CALL(...)`
//     (the error-handling wrapper around actual call statements)
static std::string preprocess_body(const std::string& body) {
  std::string out;
  out.reserve(body.size());
  bool in_str = false;
  char str_q = 0;
  size_t i = 0;
  while (i < body.size()) {
    char c = body[i];
    // Handle string literals -- preserve them verbatim
    if (in_str) {
      out.push_back(c);
      if (c == '\\' && i + 1 < body.size()) {
        out.push_back(body[i + 1]);
        i += 2;
        continue;
      }
      if (c == str_q) in_str = false;
      ++i;
      continue;
    }
    if (c == '"' || c == '\'') {
      // Check for triple-quoted (rare in C)
      in_str = true;
      str_q = c;
      out.push_back(c);
      ++i;
      continue;
    }
    // Block comment  /* ... */
    if (c == '/' && i + 1 < body.size() && body[i + 1] == '*') {
      i += 2;
      while (i + 1 < body.size() && !(body[i] == '*' && body[i + 1] == '/')) ++i;
      i += 2;
      // Replace with a space to avoid joining adjacent tokens
      out.push_back(' ');
      continue;
    }
    // Line comment  // ...
    if (c == '/' && i + 1 < body.size() && body[i + 1] == '/') {
      i += 2;
      while (i < body.size() && body[i] != '\n') ++i;
      continue;
    }
    // Preprocessor directive: a line starting with `#` (possibly after
    // whitespace).  Strip the entire line.
    if (c == '#') {
      // Check if we're at the start of a line (only whitespace before on this line)
      size_t j = out.size();
      bool at_line_start = true;
      while (j > 0 && out[j - 1] != '\n') {
        if (!std::isspace((unsigned char)out[j - 1])) { at_line_start = false; break; }
        --j;
      }
      if (at_line_start) {
        // Skip to end of line
        while (i < body.size() && body[i] != '\n') ++i;
        continue;
      }
    }
    out.push_back(c);
    ++i;
  }

  // Unwrap `if (CALL(...) < 0) __PYX_ERR(...)` patterns:
  // replace with just `CALL(...)`.
  {
    std::string out2;
    out2.reserve(out.size());
    bool in_str2 = false;
    char str_q2 = 0;
    size_t k = 0;
    while (k < out.size()) {
      char c = out[k];
      if (in_str2) {
        out2.push_back(c);
        if (c == '\\' && k + 1 < out.size()) {
          out2.push_back(out[k + 1]);
          k += 2;
          continue;
        }
        if (c == str_q2) in_str2 = false;
        ++k;
        continue;
      }
      if (c == '"' || c == '\'') {
        in_str2 = true;
        str_q2 = c;
        out2.push_back(c);
        ++k;
        continue;
      }
      // Look for `if ( ... ) __PYX_ERR(`
      // Skip leading whitespace
      if (c == 'i' && k + 1 < out.size() && out[k + 1] == 'f' &&
          (k + 2 == out.size() || !std::isalnum((unsigned char)out[k + 2]))) {
        // Check that we're at statement start (previous non-ws is ';', '{', '}', or newline)
        size_t p = out2.size();
        while (p > 0 && std::isspace((unsigned char)out2[p - 1])) --p;
        bool at_stmt_start = (p == 0 || out2[p - 1] == ';' || out2[p - 1] == '{' ||
                              out2[p - 1] == '}' || out2[p - 1] == '\n');
        if (at_stmt_start) {
          // Skip `if`
          size_t q = k + 2;
          while (q < out.size() && std::isspace((unsigned char)out[q])) ++q;
          if (q < out.size() && out[q] == '(') {
            // Find matching `)` (counting parens)
            size_t lp = q;
            int depth = 1;
            size_t rp = q + 1;
            while (rp < out.size() && depth > 0) {
              char dc = out[rp];
              if (dc == '"') {
                // Skip string
                size_t ep;
                std::string dummy;
                if (parse_c_string_literal(out, rp, dummy, ep)) { rp = ep; continue; }
              }
              if (dc == '(') ++depth;
              else if (dc == ')') --depth;
              if (depth == 0) break;
              ++rp;
            }
            if (rp < out.size() && depth == 0) {
              // Inside the if(...) is the call. Now check that after `)` there's
              // `< 0) __PYX_ERR(`. Wait — the pattern is `if (CALL(...) < 0)`.
              // The `if (...)` outer parens contain `CALL(...) < 0`. We need
              // to extract just `CALL(...)` from inside the parens.
              std::string inside = out.substr(lp + 1, rp - lp - 1);
              // Strip trailing ` < 0` or ` < (0)` from inside
              size_t lt_pos = inside.rfind('<');
              if (lt_pos != std::string::npos) {
                // Check that what follows is `0` or `(0)`
                std::string after = trim(inside.substr(lt_pos + 1));
                if (after == "0" || after == "(0)") {
                  std::string call = trim(inside.substr(0, lt_pos));
                  // Now check that after the outer `)` there's `__PYX_ERR(`
                  size_t after_rp = rp + 1;
                  while (after_rp < out.size() && std::isspace((unsigned char)out[after_rp])) ++after_rp;
                  if (after_rp + 9 < out.size() && out.substr(after_rp, 10) == "__PYX_ERR(") {
                    // Skip the rest of the `__PYX_ERR(...)` call (count parens).
                    size_t err_lp = after_rp + 9;
                    int ed = 1;
                    size_t err_rp = err_lp + 1;
                    while (err_rp < out.size() && ed > 0) {
                      char dc = out[err_rp];
                      if (dc == '(') ++ed;
                      else if (dc == ')') --ed;
                      ++err_rp;
                    }
                    // Replace the whole `if (CALL(...) < 0) __PYX_ERR(...)` with `CALL(...);`
                    out2 += call + ";";
                    k = err_rp;
                    continue;
                  }
                }
              }
            }
          }
        }
      }
      out2.push_back(c);
      ++k;
    }
    out.swap(out2);
  }

  // Remove standalone braces `{` and `}` that aren't part of an array
  // initializer or struct.  We can't easily distinguish, but in Cython output
  // the function body has very few standalone braces -- mainly the
  // `if (...) { ... }` blocks.  Replace standalone `{` or `}` lines with a
  // newline.  Keep braces inside parens (e.g. PyModuleDef = { ... }).
  std::string out2;
  out2.reserve(out.size());
  bool in_str3 = false;
  char str_q3 = 0;
  int paren_depth = 0;
  for (size_t k = 0; k < out.size(); ++k) {
    char c = out[k];
    if (in_str3) {
      out2.push_back(c);
      if (c == '\\' && k + 1 < out.size()) {
        out2.push_back(out[k + 1]);
        ++k;
        continue;
      }
      if (c == str_q3) in_str3 = false;
      continue;
    }
    if (c == '"' || c == '\'') { in_str3 = true; str_q3 = c; out2.push_back(c); continue; }
    if (c == '(') ++paren_depth;
    else if (c == ')') --paren_depth;
    if (paren_depth == 0 && (c == '{' || c == '}')) {
      // Standalone brace -- check if the rest of the line is just whitespace
      size_t p = k + 1;
      while (p < out.size() && out[p] != '\n' && std::isspace((unsigned char)out[p])) ++p;
      size_t q = k;
      while (q > 0 && out[q - 1] != '\n' && std::isspace((unsigned char)out[q - 1])) --q;
      bool only_ws_before = (q == 0 || out[q - 1] == '\n');
      bool only_ws_after = (p >= out.size() || out[p] == '\n');
      if (only_ws_before && only_ws_after) {
        // Replace with newline
        out2.push_back('\n');
        k = p;  // skip to end of line (loop's ++k will move past newline)
        continue;
      }
    }
    out2.push_back(c);
  }
  return out2;
}

static std::vector<std::string> decode_body(const std::string& body, DecodeCtx& ctx) {
  std::string cleaned = preprocess_body(body);
  std::vector<std::string> stmts = split_statements(cleaned);
  std::vector<std::string> out;
  for (auto& s : stmts) {
    StmtResult r;
    if (try_decode_stmt(s, ctx, r)) {
      if (!r.py_stmt.empty()) out.push_back(r.py_stmt);
    } else if (ctx.debug) {
      ctx.debug->push_back("[unmatched] " + s);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
//  Stage 5: Module body extractor
// ---------------------------------------------------------------------------

static bool find_module_init_body(const std::string& csrc, std::string& body) {
  // The function signature may be split by #if/#endif preprocessor guards.
  // There may also be a forward declaration that ends with ';'.  We iterate
  // over all matches of the regex and use the first one that has a '{' (the
  // actual definition body).
  static const std::regex re_sig(
      R"PYREGEX((?:static\s+)?(?:CYTHON_SMALL_CODE\s+)?int\s+__pyx_pymod_exec_[A-Za-z0-9_]+\s*\([^)]*\))PYREGEX");
  auto sig_begin = std::sregex_iterator(csrc.begin(), csrc.end(), re_sig);
  auto sig_end = std::sregex_iterator();
  for (auto sig_it = sig_begin; sig_it != sig_end; ++sig_it) {
    size_t after = (size_t)(*sig_it).position() + (*sig_it)[0].length();
    size_t lbrace = std::string::npos;
    // Walk forward one character at a time. At the start of each line
    // (i.e. just after a '\n' or at file start), if we see '#' skip the
    // entire line. Otherwise skip whitespace. If we see '{', we're done.
    // If we see ';' before '{', this is a forward declaration -- skip.
    bool at_line_start = true;
    while (after < csrc.size()) {
      char c = csrc[after];
      if (c == '\n') {
        ++after;
        at_line_start = true;
        continue;
      }
      if (at_line_start) {
        // Skip leading whitespace on the line
        size_t p = after;
        while (p < csrc.size() && (csrc[p] == ' ' || csrc[p] == '\t')) ++p;
        if (p < csrc.size() && csrc[p] == '#') {
          // Skip to end of line
          while (after < csrc.size() && csrc[after] != '\n') ++after;
          continue;
        }
        if (p < csrc.size() && csrc[p] == '{') {
          lbrace = p;
          break;
        }
        // Otherwise, this line is not a preprocessor directive and not
        // the brace. We should still scan it for the brace.
        at_line_start = false;
      } else {
        if (c == '{') { lbrace = after; break; }
        if (c == ';') break;  // forward declaration, skip
        if (!std::isspace((unsigned char)c)) {
          // Some unexpected non-whitespace -- break
          break;
        }
        ++after;
      }
    }
    if (lbrace == std::string::npos) continue;  // try next match
    int depth = 1;
    size_t i = lbrace + 1;
    while (i < csrc.size() && depth > 0) {
      char c = csrc[i];
      if (c == '"') {
        std::string dummy; size_t ep;
        if (parse_c_string_literal(csrc, i, dummy, ep)) { i = ep; continue; }
      }
      if (c == '{') ++depth;
      else if (c == '}') --depth;
      ++i;
    }
    body = csrc.substr(lbrace + 1, i - lbrace - 2);
    return true;
  }
  // Fallback: PyMODINIT_FUNC PyInit_<module>(void) { ... }
  {
    static const std::regex re_init(
        R"(PyMODINIT_FUNC\s+PyObject\s*\*\s*PyInit_[A-Za-z0-9_]+\s*\(\s*(?:void)?\s*\)\s*\{)");
    std::smatch m;
    if (std::regex_search(csrc, m, re_init)) {
      size_t lbrace = (size_t)m.position() + m[0].length() - 1;
      int depth = 1;
      size_t i = lbrace + 1;
      while (i < csrc.size() && depth > 0) {
        char c = csrc[i];
        if (c == '"') {
          std::string dummy; size_t ep;
          if (parse_c_string_literal(csrc, i, dummy, ep)) { i = ep; continue; }
        }
        if (c == '{') ++depth;
        else if (c == '}') --depth;
        ++i;
      }
      body = csrc.substr(lbrace + 1, i - lbrace - 2);
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
//  Stage 6: Emitter
// ---------------------------------------------------------------------------

static std::string emit_python(const SymbolTable& st,
                               const std::vector<FuncDef>& funcs,
                               const std::vector<std::string>& module_stmts,
                               const std::vector<std::string>& debug_log,
                               bool emit_debug) {
  std::ostringstream out;
  out << "# ============================================================================\n";
  out << "#  Recovered by pyx_decomp  --  Cython C-source -> Python decompiler\n";
  out << "#  Module:    " << st.module_name << "\n";
  out << "#  Filename:  " << (st.module_filename.empty() ? "<unknown>.py" : st.module_filename) << "\n";
  out << "#  Strings:   " << st.by_cname.size() << " resolved\n";
  out << "#  Functions: " << funcs.size() << "\n";
  out << "#  Module-level stmts: " << module_stmts.size() << "\n";
  out << "# ============================================================================\n\n";

  // Build a set of function names that are already in the module body
  // (emitted via the CyFunction marker).  We won't emit them at the top.
  std::set<std::string> emitted_in_module;
  for (const auto& s : module_stmts) {
    if (starts_with(s, "def ")) {
      size_t p = 4;
      while (p < s.size() && (std::isalnum((unsigned char)s[p]) || s[p] == '_')) ++p;
      emitted_in_module.insert(s.substr(4, p - 4));
    }
  }

  for (const auto& f : funcs) {
    if (emitted_in_module.count(f.py_name)) continue;
    if (f.args.empty()) out << "def " << f.py_name << "():\n";
    else {
      out << "def " << f.py_name << "(";
      for (size_t i = 0; i < f.args.size(); ++i) {
        if (i) out << ", ";
        out << f.args[i];
      }
      out << "):\n";
    }
    if (f.py_body.empty()) out << "    pass  # body not recovered\n";
    else {
      for (auto& l : f.py_body) {
        // Indent multi-line stmts by 4 spaces
        std::istringstream iss(l);
        std::string line;
        bool first = true;
        while (std::getline(iss, line)) {
          if (!first) out << "\n";
          out << "    " << line;
          first = false;
        }
        out << "\n";
      }
    }
    out << "\n";
  }

  // Post-process module statements: convert any statement containing unresolved
  // C API calls (like __Pyx_PyObject_FastCall, __pyx_mstate_global->, etc.) to a comment.
  // This makes the output syntactically valid Python even when we can't fully decompile.
  auto sanitize_stmt = [](const std::string& s) -> std::string {
    // Check for unresolved C API patterns
    bool has_unresolved = false;
    for (const auto& pat : {
        "__Pyx_", "__pyx_mstate", "__pyx_t_", "__pyx_tuple[",
        "__pyx_slice[", "__pyx_int[", "__pyx_codeobj",
        "PyObject_", "PyDict_", "PyList_", "PyUnicode_",
        "PyTuple_", "PySlice_", "PyLong_", "PyInt_",
        "Py_None", "Py_True", "Py_False",
        "->", "(PyObject*", "unlikely(", "likely(",
        "__PYX_ERR", "__pyx_L", "goto ", "return 0",
        "return -1", "return __pyx",
    }) {
      if (s.find(pat) != std::string::npos) { has_unresolved = true; break; }
    }
    if (has_unresolved) {
      // Convert to a comment, escaping any special chars
      std::string escaped = s;
      // Replace newlines with "\n# "
      for (size_t i = 0; i < escaped.size(); ++i) {
        if (escaped[i] == '\n') { escaped.replace(i, 1, "\n# "); i += 2; }
      }
      return "# [unresolved] " + escaped;
    }
    return s;
  };

  std::vector<std::string> sanitized_stmts;
  sanitized_stmts.reserve(module_stmts.size());
  for (const auto& s : module_stmts) {
    sanitized_stmts.push_back(sanitize_stmt(s));
  }

  for (const auto& s : sanitized_stmts) out << s << "\n";

  if (emit_debug && !debug_log.empty()) {
    out << "\n# --- debug log ---\n";
    for (auto& l : debug_log) out << "# " << l << "\n";
  }
  return out.str();
}

// ---------------------------------------------------------------------------
//  Stage 7: Binary / stripped input scanner
// ---------------------------------------------------------------------------

struct BinReport {
  std::string module_name;
  std::string source_filename;
  std::vector<std::string> py_identifiers;
  std::vector<std::string> py_filenames;
  std::vector<std::string> long_blobs;
  std::vector<std::string> all_strings;
};

static BinReport scan_binary(const std::vector<uint8_t>& bin) {
  BinReport r;
  auto strings = extract_strings_from_binary(bin, 4);
  r.all_strings = strings;

  for (auto& s : strings) {
    if (starts_with(s, "PyInit_")) {
      r.module_name = s.substr(7);
      size_t i = 0;
      while (i < r.module_name.size() &&
             (std::isalnum((unsigned char)r.module_name[i]) || r.module_name[i] == '_')) ++i;
      r.module_name = r.module_name.substr(0, i);
      break;
    }
  }
  for (auto& s : strings) {
    if (ends_with(s, ".py") && s.find_first_of(" \t\n") == std::string::npos) {
      r.py_filenames.push_back(s);
    }
  }

  std::set<std::string> seen;
  for (auto& s : strings) {
    if (s.empty() || s.size() > 64) continue;
    if (starts_with(s, "__pyx_") || starts_with(s, "Py") ||
        starts_with(s, "_Py") || starts_with(s, "cython") ||
        s.find("::") != std::string::npos || s.find('(') != std::string::npos ||
        s.find('/') != std::string::npos || s.find(' ') != std::string::npos) continue;
    bool valid = true;
    for (char c : s) {
      if (!(std::isalnum((unsigned char)c) || c == '_')) { valid = false; break; }
    }
    if (!valid) continue;
    if (seen.insert(s).second) r.py_identifiers.push_back(s);
  }

  for (auto& s : strings) {
    if (s.size() < 100) continue;
    int alnum = 0;
    for (char c : s) if (std::isalnum((unsigned char)c)) ++alnum;
    if (alnum * 100 > (int)s.size() * 90) r.long_blobs.push_back(s);
  }

  if (!r.module_name.empty()) {
    std::string expected = r.module_name + ".py";
    for (auto& f : r.py_filenames) if (f == expected) { r.source_filename = f; break; }
  }
  if (r.source_filename.empty() && !r.py_filenames.empty())
    r.source_filename = r.py_filenames.front();
  return r;
}

static std::string emit_binary_skeleton(const BinReport& r) {
  std::ostringstream out;
  out << "# ============================================================================\n";
  out << "#  Recovered by pyx_decomp  --  STRIPPED BINARY mode\n";
  out << "#  Module:    " << (r.module_name.empty() ? "<unknown>" : r.module_name) << "\n";
  out << "#  Filename:  " << (r.source_filename.empty() ? "<unknown>.py" : r.source_filename) << "\n";
  out << "#  Strings:   " << r.all_strings.size() << " extracted\n";
  out << "#  Identifiers: " << r.py_identifiers.size() << " candidate\n";
  out << "#  Long blobs: " << r.long_blobs.size() << "\n";
  out << "# ============================================================================\n\n";
  out << "# NOTE: This binary is stripped. Only string constants are recoverable.\n";
  out << "#       The function bodies cannot be reconstructed without symbol info.\n\n";
  if (!r.module_name.empty())
    out << "# Module name recovered from PyInit_<module> symbol\n\n";
  if (!r.py_filenames.empty()) {
    out << "# Source filenames found in .rodata:\n";
    for (auto& f : r.py_filenames) out << "#   " << f << "\n";
    out << "\n";
  }
  if (!r.py_identifiers.empty()) {
    out << "# Candidate Python identifiers (used as imports / names / attrs):\n";
    for (auto& id : r.py_identifiers) out << "#   " << id << "\n";
    out << "\n";
  }
  if (!r.long_blobs.empty()) {
    out << "# Long string constants (likely encoded payloads):\n";
    for (auto& b : r.long_blobs) {
      out << "#   " << b.substr(0, 80) << (b.size() > 80 ? "..." : "") << "  (len=" << b.size() << ")\n";
    }
    out << "\n";
  }
  out << "# --- Best-effort skeleton ---\n";
  out << "# def <function_name>(<args>):\n";
  out << "#     ...  # body not recoverable from stripped binary\n\n";
  return out.str();
}

// ---------------------------------------------------------------------------
//  Stage 8: Main orchestration
// ---------------------------------------------------------------------------

struct Options {
  std::string input_path;
  std::string output_path;
  std::string json_path;
  bool debug = false;
};

static void usage(const char* prog) {
  std::cerr << "Usage: " << prog << " <input.c|input.py|input.so|input.bin> [-o output.py] [--json report.json] [--debug]\n";
}

} // namespace pyx

int main(int argc, char** argv) {
  using namespace pyx;
  Options opt;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-o" && i + 1 < argc) { opt.output_path = argv[++i]; continue; }
    if (a == "--json" && i + 1 < argc) { opt.json_path = argv[++i]; continue; }
    if (a == "--debug") { opt.debug = true; continue; }
    if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    if (a.empty() || a[0] == '-') { usage(argv[0]); return 1; }
    if (opt.input_path.empty()) opt.input_path = a;
  }
  if (opt.input_path.empty()) { usage(argv[0]); return 1; }
  if (opt.output_path.empty()) {
    size_t dot = opt.input_path.find_last_of('.');
    if (dot == std::string::npos) opt.output_path = opt.input_path + ".recovered.py";
    else opt.output_path = opt.input_path.substr(0, dot) + ".recovered.py";
  }

  std::string err;
  Input in = load_input(opt.input_path, err);
  if (!err.empty()) { std::cerr << "error: " << err << "\n"; return 2; }

  std::cerr << "[*] input kind: ";
  switch (in.kind) {
    case InputKind::CSource:  std::cerr << "C source"; break;
    case InputKind::PyWrapper: std::cerr << "Python wrapper (extracting embedded C_SOURCE)"; break;
    case InputKind::Binary:  std::cerr << "Binary (stripped mode)"; break;
    default: std::cerr << "unknown"; break;
  }
  std::cerr << "\n";

  if (in.kind == InputKind::Binary) {
    std::cerr << "[*] scanning binary for strings...\n";
    BinReport r = scan_binary(in.bin);
    std::string out = emit_binary_skeleton(r);
    std::ofstream f(opt.output_path);
    if (!f) { std::cerr << "cannot write: " << opt.output_path << "\n"; return 3; }
    f << out;
    std::cerr << "[+] wrote " << opt.output_path << "\n";
    if (!opt.json_path.empty()) {
      std::ofstream jf(opt.json_path);
      jf << "{\n  \"mode\": \"binary\",\n  \"module\": \"" << r.module_name << "\",\n"
         << "  \"source_filename\": \"" << r.source_filename << "\",\n"
         << "  \"n_strings\": " << r.all_strings.size() << ",\n"
         << "  \"n_identifiers\": " << r.py_identifiers.size() << ",\n"
         << "  \"n_long_blobs\": " << r.long_blobs.size() << "\n}\n";
    }
    return 0;
  }

  std::cerr << "[*] C source size: " << in.c_source.size() << " bytes\n";
  SymbolTable st;
  if (!build_symbol_table(in.c_source, st, err)) { std::cerr << "error: " << err << "\n"; return 4; }
  std::cerr << "[*] module: " << st.module_name << "  filename: " << st.module_filename << "\n";
  std::cerr << "[*] resolved " << st.by_cname.size() << " symbols\n";

  auto funcs = extract_functions(in.c_source, st);
  std::cerr << "[*] found " << funcs.size() << " function(s)\n";

  std::vector<std::string> debug_log;
  for (auto& f : funcs) {
    DecodeCtx ctx(st);
    ctx.is_function = true;
    for (auto& a : f.args) ctx.varmap["__pyx_v_" + a] = a;
    if (opt.debug) ctx.debug = &debug_log;
    f.py_body = decode_body(f.body_lines[0], ctx);
    std::cerr << "    - " << f.py_name << "(";
    for (size_t i = 0; i < f.args.size(); ++i) {
      if (i) std::cerr << ", ";
      std::cerr << f.args[i];
    }
    std::cerr << ")  ->  " << f.py_body.size() << " stmt(s)\n";
  }

  std::vector<std::string> module_stmts;
  std::string mod_body;
  if (find_module_init_body(in.c_source, mod_body)) {
    DecodeCtx ctx(st);
    ctx.is_function = false;
    if (opt.debug) ctx.debug = &debug_log;
    module_stmts = decode_body(mod_body, ctx);

    for (auto& s : module_stmts) {
      size_t p = s.find(" = __CYFUNCTION__:");
      if (p != std::string::npos) {
        std::string name = s.substr(0, p);
        bool found = false;
        for (auto& f : funcs) {
          if (f.py_name == name) {
            std::ostringstream defn;
            if (f.args.empty()) defn << "def " << f.py_name << "():";
            else {
              defn << "def " << f.py_name << "(";
              for (size_t i = 0; i < f.args.size(); ++i) {
                if (i) defn << ", ";
                defn << f.args[i];
              }
              defn << "):";
            }
            s = defn.str();
            if (f.py_body.empty()) s += "\n    pass  # body not recovered";
            else for (auto& bl : f.py_body) s += "\n    " + bl;
            found = true;
            break;
          }
        }
        if (!found) {
          // Function not found in funcs list — emit a stub
          s = "def " + name + "():\n    pass  # body not recovered";
        }
      }
    }
  } else {
    std::cerr << "[!] could not find module init body\n";
  }
  std::cerr << "[*] module-level: " << module_stmts.size() << " stmt(s)\n";

  std::string py = emit_python(st, funcs, module_stmts, debug_log, opt.debug);
  std::ofstream of(opt.output_path);
  if (!of) { std::cerr << "cannot write: " << opt.output_path << "\n"; return 5; }
  of << py;
  std::cerr << "[+] wrote " << opt.output_path << "\n";

  if (!opt.json_path.empty()) {
    std::ofstream jf(opt.json_path);
    jf << "{\n  \"mode\": \"text\",\n  \"module\": \"" << st.module_name << "\",\n"
       << "  \"source_filename\": \"" << st.module_filename << "\",\n"
       << "  \"n_symbols\": " << st.by_cname.size() << ",\n"
       << "  \"n_functions\": " << funcs.size() << ",\n"
       << "  \"n_module_stmts\": " << module_stmts.size() << ",\n"
       << "  \"functions\": [\n";
    for (size_t i = 0; i < funcs.size(); ++i) {
      jf << "    {\"name\": \"" << funcs[i].py_name << "\", \"args\": [";
      for (size_t k = 0; k < funcs[i].args.size(); ++k) {
        if (k) jf << ", ";
        jf << "\"" << funcs[i].args[k] << "\"";
      }
      jf << "], \"n_body_stmts\": " << funcs[i].py_body.size() << "}";
      if (i + 1 < funcs.size()) jf << ",";
      jf << "\n";
    }
    jf << "  ]\n}\n";
  }
  return 0;
}
