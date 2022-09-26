// Automatically generated by xdrgen
// DO NOT EDIT or your changes may be overwritten

package MyXDR;


import java.io.IOException;

import com.google.common.base.Objects;
import java.util.Arrays;

// === xdr source ============================================================

//  struct MyStruct
//  {
//      int    someInt;
//      int64  aBigInt;
//      opaque someOpaque[10];
//      string someString<>;
//      string maxString<100>;
//  };

//  ===========================================================================
public class MyStruct implements XdrElement {
  public MyStruct () {}
  private Integer someInt;
  public Integer getSomeInt() {
    return this.someInt;
  }
  public void setSomeInt(Integer value) {
    this.someInt = value;
  }
  private Int64 aBigInt;
  public Int64 getABigInt() {
    return this.aBigInt;
  }
  public void setABigInt(Int64 value) {
    this.aBigInt = value;
  }
  private byte[] someOpaque;
  public byte[] getSomeOpaque() {
    return this.someOpaque;
  }
  public void setSomeOpaque(byte[] value) {
    this.someOpaque = value;
  }
  private XdrString someString;
  public XdrString getSomeString() {
    return this.someString;
  }
  public void setSomeString(XdrString value) {
    this.someString = value;
  }
  private XdrString maxString;
  public XdrString getMaxString() {
    return this.maxString;
  }
  public void setMaxString(XdrString value) {
    this.maxString = value;
  }
  public static void encode(XdrDataOutputStream stream, MyStruct encodedMyStruct) throws IOException{
    stream.writeInt(encodedMyStruct.someInt);
    Int64.encode(stream, encodedMyStruct.aBigInt);
    int someOpaquesize = encodedMyStruct.someOpaque.length;
    stream.write(encodedMyStruct.getSomeOpaque(), 0, someOpaquesize);
    encodedMyStruct.someString.encode(stream);
    encodedMyStruct.maxString.encode(stream);
  }
  public void encode(XdrDataOutputStream stream) throws IOException {
    encode(stream, this);
  }
  public static MyStruct decode(XdrDataInputStream stream) throws IOException {
    MyStruct decodedMyStruct = new MyStruct();
    decodedMyStruct.someInt = stream.readInt();
    decodedMyStruct.aBigInt = Int64.decode(stream);
    int someOpaquesize = 10;
    decodedMyStruct.someOpaque = new byte[someOpaquesize];
    stream.read(decodedMyStruct.someOpaque, 0, someOpaquesize);
    decodedMyStruct.someString = XdrString.decode(stream, );
    decodedMyStruct.maxString = XdrString.decode(stream, 100);
    return decodedMyStruct;
  }
  @Override
  public int hashCode() {
    return Objects.hashCode(this.someInt, this.aBigInt, Arrays.hashCode(this.someOpaque), this.someString, this.maxString);
  }
  @Override
  public boolean equals(Object object) {
    if (!(object instanceof MyStruct)) {
      return false;
    }

    MyStruct other = (MyStruct) object;
    return Objects.equal(this.someInt, other.someInt) && Objects.equal(this.aBigInt, other.aBigInt) && Arrays.equals(this.someOpaque, other.someOpaque) && Objects.equal(this.someString, other.someString) && Objects.equal(this.maxString, other.maxString);
  }

  public static final class Builder {
    private Integer someInt;
    private Int64 aBigInt;
    private byte[] someOpaque;
    private XdrString someString;
    private XdrString maxString;

    public Builder someInt(Integer someInt) {
      this.someInt = someInt;
      return this;
    }

    public Builder aBigInt(Int64 aBigInt) {
      this.aBigInt = aBigInt;
      return this;
    }

    public Builder someOpaque(byte[] someOpaque) {
      this.someOpaque = someOpaque;
      return this;
    }

    public Builder someString(XdrString someString) {
      this.someString = someString;
      return this;
    }

    public Builder maxString(XdrString maxString) {
      this.maxString = maxString;
      return this;
    }

    public MyStruct build() {
      MyStruct val = new MyStruct();
      val.setSomeInt(someInt);
      val.setABigInt(aBigInt);
      val.setSomeOpaque(someOpaque);
      val.setSomeString(someString);
      val.setMaxString(maxString);
      return val;
    }
  }
}