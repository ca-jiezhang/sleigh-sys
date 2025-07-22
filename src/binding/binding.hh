#include "rust/cxx.h"

#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <stdexcept>

#include "loadimage.hh"
#include "sleigh.hh"

namespace ghidra {

//////////////////////////////////////////////////////////////////////////////
// proxy class

#define PROXY_OBJECT()  inner_

#define BEGIN_PTR_PROXY_CLASS(name) \
  class R##name { \
  private:                \
    name *  PROXY_OBJECT(); \
  public:                 \
    R##name(name * value): inner_(value)

#define BEGIN_CONST_PROXY_CLASS(name) \
  class R##name { \
  private:                \
    name  PROXY_OBJECT(); \
  public:                 \
    R##name(const name & value) : inner_(value)

#define BEGIN_PROXY_CLASS(name) \
  class R##name { \
  private:                \
    name  PROXY_OBJECT(); \
  public:                 \
    R##name(name & value) : inner_(value)

#define END_PROXY_CLASS() };

// proxy class of AddrSpace -> RAddrSpace
class RAddrSpace {
private:
  AddrSpace * inner_;

public:
  RAddrSpace(AddrSpace * space)
    :inner_(space)
  {}

  rust::Str name() const {
    return inner_->getName();
  }

  spacetype kind() const {
    return inner_->getType();
  }

}; // RAddrSpace

// proxy class of Address -> RAddress
class RAddress {
private:
  Address inner_;

public:
  RAddress(Address & addr)
    : inner_(addr)
  {
  }

  std::unique_ptr<RAddrSpace> space() const {
    return std::make_unique<RAddrSpace>(inner_.getSpace());
  }

  uint64_t offset() const {
    return inner_.getOffset();
  }

}; // RAddress

class RVarnodeData {
private:
  VarnodeData inner_;

public:
  RVarnodeData(VarnodeData & data)
    : inner_(data)
  {
  }

  std::unique_ptr<RAddrSpace> space() const {
    return std::make_unique<RAddrSpace>(inner_.space);
  }

  uint64_t offset() const {
    return inner_.offset;
  }

  uint32_t size() const {
    return inner_.size;
  }

  rust::String register_name() const {
    std::string reg_name = inner_.space->getTrans()->getRegisterName(inner_.space, inner_.offset, inner_.size);
    if (reg_name.empty()) {
      throw std::invalid_argument("the VarnodeData is not a valid register");
    }

    return reg_name;
  }

  rust::String user_defined_op_name() const {
    std::vector<std::string> op_names;

    inner_.space->getTrans()->getUserOpNames(op_names);
    if (inner_.offset >= op_names.size()) {
      throw std::out_of_range("invalid user op name");
    }

    return op_names[inner_.offset];
  }

  std::unique_ptr<RAddrSpace> space_from_const() const {
    return std::make_unique<RAddrSpace>(inner_.getSpaceFromConst());
  }
}; // RVarnodeData

//////////////////////////////////////////////////////////////////////////////
// class RLoadImage

class RLoadImage: public LoadImage {
private:
  uint64_t  base_;
  uint32_t  size_;
  const uint8_t * data_;

public:
  RLoadImage()
    : LoadImage("<nofile>")
    , base_(0)
    , size_(0)
    , data_(nullptr)
  {}

  void set_data(uint64_t base, const uint8_t * data, uint32_t size) {
    base_ = base;
    data_ = data;
    size_ = size;
  }

  void loadFill(uint1 *ptr, int4 size, const Address &addr) {
    uintb start = addr.getOffset();
    uintb max = base_ + size_;

    if (start >= max || start < base_) {
      std::memset(ptr, 0, size);
    } else {
      for (int4 i=0; i<size; i++) {
        uintb offs = start + i;
        if (offs < base_ || offs >= max) {
          ptr[i] = 0;
        } else {
          int4 delta = (int4)(offs - base_);
          ptr[i] = data_[delta];
        }
      }
    }
  }

  virtual std::string getArchType() const {
    return "simple";
  }

  virtual void adjustVma(long adjust) {}
}; // RLoadImage

//////////////////////////////////////////////////////////////////////////////
// class RAssemblyInstruction

class RAssemblyInstruction {
private:
  uint64_t  addr_;
  uint32_t  size_;
  std::string   mnem_;
  std::string   body_;

public:
  RAssemblyInstruction(const Address & addr, const std::string & mnem, const std::string & body)
    : addr_(addr.getOffset())
    , mnem_(mnem)
    , body_(body)
  {}

  uint64_t address() const {
    return addr_;
  }

  rust::str mnem() const {
    return mnem_;
  }

  rust::str body() const {
    return body_;
  }

  uint32_t size() const {
    return size_;
  }

  void set_size(uint32_t size) {
    size_ = size;
  }
}; // RAssemblyInstruction


//////////////////////////////////////////////////////////////////////////////
// DisassemblyEmit
class RAssemblyEmit: public AssemblyEmit {
private:
  std::unique_ptr<RAssemblyInstruction> code_;

public:
  void dump(const Address &addr, const std::string &mnem, const std::string &body) {
    code_ = std::make_unique<RAssemblyInstruction>(addr, mnem, body);
  }

  std::unique_ptr<RAssemblyInstruction> take_code() {
    return std::move(code_);
  }
}; // RAssemblyEmit

//////////////////////////////////////////////////////////////////////////////
// class RPcode and related classes

struct RPcode {
  OpCode  opc_;
  std::optional<RVarnodeData>  output_;
  std::vector<RVarnodeData>    inputs_;

  //
  // methods:
  //

  OpCode opcode() const {
    return opc_;
  }

  const RVarnodeData & output() const {
    if (!output_.has_value()) {
      throw std::invalid_argument("no output variable");
    }

    return *output_;
  }

  uint32_t argc() const {
    return inputs_.size();
  }

  const RVarnodeData & argv(uint32_t index) const {
    return inputs_.at(index);
  }
}; // RPcode

struct RTranslation {
  uint64_t  instruction_address_;
  uint64_t  next_instruction_address_;
  uint32_t  instruction_size_;
  std::vector<RPcode> codes_;

  //
  // methods:
  //

  uint64_t instruction_address() const {
    return instruction_address_;
  }

  uint64_t next_instruction_address() const {
    return next_instruction_address_;
  }

  uint32_t instruction_size() const {
    return instruction_size_;
  }

  uint32_t count() const {
    return codes_.size();
  }

  const RPcode & code(uint32_t index) const {
    return codes_.at(index);
  }
}; // RTranslation

#define DEFAULT_PCODE_CACHE_SIZE 0x100

class RPcodeEmit: public PcodeEmit {
private:
  std::vector<RPcode> codes_;

public:
  RPcodeEmit() {
    codes_.reserve(DEFAULT_PCODE_CACHE_SIZE);
  }

  void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *invars, int4 num_invars) {
    RPcode code;

    code.opc_ = opc;
    
    if (outvar) {
      code.output_.emplace(*outvar);
    }

    if (num_invars > 0) {
      code.inputs_.reserve(num_invars);

      for (int i=0; i<num_invars; i++) {
        code.inputs_.emplace_back(invars[i]);
      }
    }

    codes_.push_back(std::move(code));
  }

  std::vector<RPcode> && take_codes() {
    return std::move(codes_);
  }
}; // RPcodeEmit

//////////////////////////////////////////////////////////////////////////////
// class Context

class RContext {
private:
  ContextInternal ctx_;
  DocumentStorage doc_;
  RLoadImage      loader_;

  std::unique_ptr<Sleigh> sleigh_;

public:
  RContext(rust::Str filename) {
    AttributeId::initialize();
    ElementId::initialize();

    std::string sla_name(filename.data(), filename.size());

    istringstream ss(sla_name);
    Element *root = doc_.parseDocument(ss)->getRoot();
    doc_.registerTag(root);

    reset();
  }

  void reset() {
    sleigh_.reset(new Sleigh(&loader_, &ctx_));
    sleigh_->initialize(doc_);
  }

  void set_variable_default(rust::Str name, uintm value) {
    std::string var_name(name.data(), name.size());
    ctx_.setVariableDefault(var_name, value);
  }

  std::unique_ptr<RAssemblyInstruction> disassemble(rust::Slice<const uint8_t> data, uint64_t addr) {
    loader_.set_data(addr, data.data(), data.size());

    Address vaddr(sleigh_->getDefaultCodeSpace(), addr);
    RAssemblyEmit emit;

    std::unique_ptr<RAssemblyInstruction> code;

    try {
      uint32_t size = sleigh_->printAssembly(emit, vaddr);
      code = emit.take_code();
      code->set_size(size);
    } catch (...) {
      code.reset();
    }

    if (!code) {
      throw std::invalid_argument("failed to disassemble instruction");
    }

    return code;
  }

  std::unique_ptr<RTranslation> translate(rust::Slice<const uint8_t> data, uint64_t addr) {
    loader_.set_data(addr, data.data(), data.size());

    auto trans = std::make_unique<RTranslation>();
    trans->instruction_address_ = addr;

    Address vaddr(sleigh_->getDefaultCodeSpace(), addr);
    RPcodeEmit emit;

    try {
      trans->instruction_size_ = sleigh_->oneInstruction(emit, vaddr);
      trans->next_instruction_address_ = trans->instruction_address_ + trans->instruction_size_;
      trans->codes_ = emit.take_codes();
    } catch (...) {
      trans.reset();
    }

    if (!trans) {
      throw std::invalid_argument("failed to translate instructoni");
    }

    return trans;
  }
}; // RContext

//
// creata a new context
//
std::unique_ptr<RContext> new_context(rust::Str filename) {
  return std::make_unique<RContext>(filename);
}

} // namespace ghidra

