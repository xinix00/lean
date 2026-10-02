#!/usr/bin/env python3
"""Generate independent wire fixtures with the retained Go v1.2.0 tag.
The old Go tree stays outside the checkout; only its two wire codecs are used.
"""
from pathlib import Path
import subprocess,tempfile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
TEST=r'''package leannet
import("os";"testing")
func TestFixture(t *testing.T){
 src:=llAddrFromMAC([6]byte{2,0,0,0,0,2});dst:=llAddrFromMAC([6]byte{2,0,0,0,0,1})
 data:=[]byte("Go IPv6 fixture")
 f:=make([]byte,14+40+8+len(data));copy(f[:6],[]byte{2,0,0,0,0,1});copy(f[6:12],[]byte{2,0,0,0,0,2});f[12]=0x86;f[13]=0xdd
 copy(f[62:],data);if _,e:=PutUDP6(f[54:],5540,9999,src,dst,len(data));e!=nil{t.Fatal(e)}
 if _,e:=PutIPv6(f[14:],17,64,src,dst,8+len(data));e!=nil{t.Fatal(e)}
 if e:=os.WriteFile("udp.bin",f,0600);e!=nil{t.Fatal(e)}
 body:=make([]byte,12+8+32+24);copy(body[12:20],[]byte{1,1,2,0,0,0,0,2})
 p:=body[20:52];p[0]=3;p[1]=4;p[2]=64;p[3]=0xc0;p[7]=60;p[11]=30;p[16]=0xfd;p[17]=1
 r:=body[52:];r[0]=24;r[1]=3;r[2]=64;r[7]=90;r[8]=0xfd;r[9]=2
 f=make([]byte,14+40+4+len(body));copy(f[:6],[]byte{0x33,0x33,0,0,0,1});copy(f[6:12],[]byte{2,0,0,0,0,2});f[12]=0x86;f[13]=0xdd
 if _,e:=putNDP(f[54:],134,body,src,allNodes6);e!=nil{t.Fatal(e)}
 if _,e:=PutIPv6(f[14:],58,255,src,allNodes6,4+len(body));e!=nil{t.Fatal(e)}
 if e:=os.WriteFile("ra.bin",f,0600);e!=nil{t.Fatal(e)}
}
'''
with tempfile.TemporaryDirectory(prefix='leannet-go-ipv6-') as name:
 d=Path(name)
 for f in ['frame.go','frame6.go']:
  (d/f).write_bytes(subprocess.check_output(['git','show',f'v1.2.0:leannet/{f}'],cwd=ROOT))
 (d/'go.mod').write_text('module ipv6fixtures\n\ngo 1.26\n')
 (d/'fixture_test.go').write_text(TEST+'\n// IPv4-only helper referenced by frame.go; not used by these IPv6 fixtures.\nfunc isLinkLocalMulticast(ip [4]byte) bool { return ip[0]==224 && ip[1]==0 && ip[2]==0 && ip[3]!=0 }\n')
 subprocess.run(['go','test','-run','TestFixture','-count=1'],cwd=d,check=True)
 for f in ['udp.bin','ra.bin']:(HERE/f).write_bytes((d/f).read_bytes())
