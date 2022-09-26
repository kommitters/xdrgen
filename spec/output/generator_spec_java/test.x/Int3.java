// Automatically generated by xdrgen
// DO NOT EDIT or your changes may be overwritten

package MyXDR;


import java.io.IOException;

import com.google.common.base.Objects;

// === xdr source ============================================================

//  typedef unsigned int    int3;

//  ===========================================================================
public class Int3 implements XdrElement {
  private Integer int3;

  public Int3() {}

  public Int3(Integer int3) {
    this.int3 = int3;
  }

  public Integer getInt3() {
    return this.int3;
  }

  public void setInt3(Integer value) {
    this.int3 = value;
  }

  public static void encode(XdrDataOutputStream stream, Int3  encodedInt3) throws IOException {
    stream.writeInt(encodedInt3.int3);
  }

  public void encode(XdrDataOutputStream stream) throws IOException {
    encode(stream, this);
  }
  public static Int3 decode(XdrDataInputStream stream) throws IOException {
    Int3 decodedInt3 = new Int3();
    decodedInt3.int3 = stream.readInt();
    return decodedInt3;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(this.int3);
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof Int3)) {
      return false;
    }

    Int3 other = (Int3) object;
    return Objects.equal(this.int3, other.int3);
  }
}