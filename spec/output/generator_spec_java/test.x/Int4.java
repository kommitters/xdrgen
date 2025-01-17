// Automatically generated by xdrgen
// DO NOT EDIT or your changes may be overwritten

package MyXDR;


import java.io.IOException;

import com.google.common.base.Objects;

// === xdr source ============================================================

//  typedef unsigned hyper  int4;

//  ===========================================================================
public class Int4 implements XdrElement {
  private Long int4;

  public Int4() {}

  public Int4(Long int4) {
    this.int4 = int4;
  }

  public Long getInt4() {
    return this.int4;
  }

  public void setInt4(Long value) {
    this.int4 = value;
  }

  public static void encode(XdrDataOutputStream stream, Int4  encodedInt4) throws IOException {
    stream.writeLong(encodedInt4.int4);
  }

  public void encode(XdrDataOutputStream stream) throws IOException {
    encode(stream, this);
  }
  public static Int4 decode(XdrDataInputStream stream) throws IOException {
    Int4 decodedInt4 = new Int4();
    decodedInt4.int4 = stream.readLong();
    return decodedInt4;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(this.int4);
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof Int4)) {
      return false;
    }

    Int4 other = (Int4) object;
    return Objects.equal(this.int4, other.int4);
  }
}
