// Automatically generated by xdrgen
// DO NOT EDIT or your changes may be overwritten

package MyXDR;


import java.io.IOException;

import java.util.Arrays;

// === xdr source ============================================================

//  struct LotsOfMyStructs
//  {
//      MyStruct members<>;
//  };

//  ===========================================================================
public class LotsOfMyStructs implements XdrElement {
  public LotsOfMyStructs () {}
  private MyStruct[] members;
  public MyStruct[] getMembers() {
    return this.members;
  }
  public void setMembers(MyStruct[] value) {
    this.members = value;
  }
  public static void encode(XdrDataOutputStream stream, LotsOfMyStructs encodedLotsOfMyStructs) throws IOException{
    int memberssize = encodedLotsOfMyStructs.getMembers().length;
    stream.writeInt(memberssize);
    for (int i = 0; i < memberssize; i++) {
      MyStruct.encode(stream, encodedLotsOfMyStructs.members[i]);
    }
  }
  public void encode(XdrDataOutputStream stream) throws IOException {
    encode(stream, this);
  }
  public static LotsOfMyStructs decode(XdrDataInputStream stream) throws IOException {
    LotsOfMyStructs decodedLotsOfMyStructs = new LotsOfMyStructs();
    int memberssize = stream.readInt();
    decodedLotsOfMyStructs.members = new MyStruct[memberssize];
    for (int i = 0; i < memberssize; i++) {
      decodedLotsOfMyStructs.members[i] = MyStruct.decode(stream);
    }
    return decodedLotsOfMyStructs;
  }
  @Override
  public int hashCode() {
    return Arrays.hashCode(this.members);
  }
  @Override
  public boolean equals(Object object) {
    if (!(object instanceof LotsOfMyStructs)) {
      return false;
    }

    LotsOfMyStructs other = (LotsOfMyStructs) object;
    return Arrays.equals(this.members, other.members);
  }

  public static final class Builder {
    private MyStruct[] members;

    public Builder members(MyStruct[] members) {
      this.members = members;
      return this;
    }

    public LotsOfMyStructs build() {
      LotsOfMyStructs val = new LotsOfMyStructs();
      val.setMembers(members);
      return val;
    }
  }
}