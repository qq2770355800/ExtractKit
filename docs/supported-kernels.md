# 支持的内核

内置 profile 全部来自**我们自己解析的官方镜像**（`boot.img` / `Image` → kallsyms + BTF + 反汇编 call site），
每行给的是 `Build.MODEL` / profile 名 / 匹配前缀（`release` 里必须包含 `g<hash>`）。

| 机型 | profile | 匹配前缀 |
| --- | --- | --- |
| AAK-AN00 | AAK-AN00 / 6.6.89-android15 | `6.6.89-android15-8-g3c4937385c19-abogki455778110-4k` |
| ABR-AN80 | ABR-AN80 / 6.12.38-android16 | `6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k` |
| ABR-L31 | ABR-L31 / 5.15.180-android13-8 | `5.15.180-android13-8-00018-g9b2308ac0ad6` |
| ABR-N33 | ABR-N33 / 6.12.30-android16 | `6.12.30-android16-5-ge3b2afa06218-ab14377253-4k` |
| ALT-AN00 | ALT-AN00 / 5.10.252-android12-9 | `5.10.252-android12-9-g839eb53a56c3` |
| AMG-AN00 | AMG-AN00 / 6.1.157-android14-11 | `6.1.157-android14-11-g2646292297b1` |
| AMG-AN00 | AMG-AN00 / 6.1.99-android14 | `6.1.99-android14-11-g5859fbdbad8c` |
| AMM-AN00 | AMM-AN00 / 5.15.180-android13 · 21603b4 | `5.15.180-android13-8-g21603b4ea1f9` |
| AMM-AN00 | AMM-AN00 / 5.15.180-android13 · 928f00c | `5.15.180-android13-8-g928f00c79361` |
| AMM-TN00 | AMM-TN00 / 5.15.180-android13 · 09f8933 | `5.15.180-android13-8-g09f89336e371` |
| AMM-TN00 | AMM-TN00 / 5.15.180-android13 · 4961434 | `5.15.180-android13-8-g4961434d9598` |
| AMP-AN10 | AMP-AN10 / 6.1.128-android14 · 0741060 | `6.1.128-android14-11-g07410607dc1c` |
| AMP-AN10 | AMP-AN10 / 6.1.128-android14 · 286b85f | `6.1.128-android14-11-g286b85f34ae5` |
| AMP-AN10 | AMP-AN10 / 6.1.128-android14 · bfe6fb3 | `6.1.128-android14-11-gbfe6fb35bc83` |
| AMP-AN10 | AMP-AN10 / 6.1.128-android14 · faedf8d | `6.1.128-android14-11-gfaedf8de5b24` |
| APH-AN00 | APH-AN00 / 6.12.58-android16-6 | `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k` |
| BKQ-AN10 | g45ea5e4bce8a (offsets-only) | `6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k` |
| BKQ-LGRP1 | BKQ-LGRP1 / 6.12.23-android16 | `6.12.23-android16-5-g52ffb60eb2fc-abogki436399202-4k` |
| BKQ-N49 | BKQ-N49 / 6.12.23-android16 · 13404bb | `6.12.23-android16-5-g13404bb4d51d-ab14275538-4k` |
| BKQ-N49 | BKQ-N49 / 6.12.23-android16 · a5f232d | `6.12.23-android16-5-ga5f232d1ead0-ab14083253-4k` |
| BKQ-N49 | BKQ-N49 / 6.12.38-android16 · 0de425e | `6.12.38-android16-5-g0de425e73a77-ab14804637-4k` |
| BKQ-N49 | BKQ-N49 / 6.12.38-android16 · d01bd4b | `6.12.38-android16-5-gd01bd4be3dda-ab14423277-4k` |
| BKQ-N49 | BKQ-N49 / 6.12.38-android16 · f69ca77 | `6.12.38-android16-5-gf69ca77783f8-ab14605663-4k` |
| BRM-AN00 | BRM-AN00 / 6.18.21-android17 | `6.18.21-android17-5-ge186062ea75f-abogki564062290-4k` |
| BSN-AN00 | g459a4285ccf8 (offsets-only) | `6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k` |
| BSN-AN10 | BSN-AN10 / 6.12.58-android16 | `6.12.58-android16-6-g1439620c9496-abogki524512671-4k` |
| BSN-N31 | BSN-N31 / 6.12.58-android16 | `6.12.58-android16-6-g50d6c2424b3a-ab15726793-4k` |
| BSN-N51 | BSN-N51 / 6.12.58-android16 | `6.12.58-android16-6-g09eda8c8505a-ab15950084-4k` |
| BVL-AN00 | BVL-AN00 / 6.1.157-android14-11 | `6.1.157-android14-11-g7d3922fade43` |
| BVL-AN16 | BVL-AN16 / 6.1.157-android14-11 | `6.1.157-android14-11-g84ffa64b710b` |
| BVL-AN20HP | BVL-AN20HP / 6.1.128-android14 · 84f1d56 | `6.1.128-android14-11-g84f1d56830ff` |
| BVL-AN20HP | BVL-AN20HP / 6.1.128-android14 · d4936c4 | `6.1.128-android14-11-gd4936c483bc7` |
| BVL-AN20HP | BVL-AN20HP / 6.1.99-android14 | `6.1.99-android14-11-g7c11f5fcbcdb` |
| BVL-N19 | BVL-N19 / 6.1.128-android14 | `6.1.128-android14-11-g58deda01e47b-ab14263620` |
| BVL-N19 | BVL-N19 / 6.1.157-android14 · 3416ba8 | `6.1.157-android14-11-g3416ba8f00e3-ab15314546` |
| BVL-N19 | BVL-N19 / 6.1.157-android14 · c7dd3fa | `6.1.157-android14-11-gc7dd3fa941b3-ab15371444` |
| CGL-W60 | CGL-W60 / 6.1.157-android14-11 | `6.1.157-android14-11-gaaa383620ebf` |
| CLE-AN00 | CLE-AN00 / 6.1.128-android14 | `6.1.128-android14-11-ge9da27488f45` |
| ELP-AN00 | ELP-AN00 / 6.1.128-android14-11 | `6.1.128-android14-11-gec1055c9cbb5` |
| JDY-L43P | JDY-L43P / 6.6.118-android15 | `6.6.118-android15-8-g8b54898e6705-4k` |
| MAA-AN10 | MAA-AN10 / 5.15.180-android13 | `5.15.180-android13-8-gb652f2620acb` |
| MAG-AN00 | MAG-AN00 / 5.15.180-android13 | `5.15.180-android13-8-g938a6e3184bd` |
| MLY-AN00 | gfde7767f6ef6 (offsets-only) | `6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k` |
| MTN-AN00 | MTN-AN00/AN80 / 6.1.157-android14-11 | `6.1.157-android14-11-g19a495a97bff` |
| PGT-AN10 | PGT-AN10 / 5.15.180-android13 · 1c54d61 | `5.15.180-android13-8-g1c54d617912d` |
| PGT-AN10 | PGT-AN10 / 5.15.180-android13 · 49611f0 | `5.15.180-android13-8-g49611f0c0136` |
| PPG-AN00 | HONOR PPG-AN00 / 6.6.118-android15-8 | `6.6.118-android15-8-g554929766a0d` |
| PPG-AN00 | PPG-AN00 / 6.6.89-android15-8 | `6.6.89-android15-8-g660f666ec112` |
| PTP-AN10 | PTP-AN10 / 6.6.118-android15-8 | `6.6.118-android15-8-ga812a1946391-abogki576098434-4k` |
| PTP-AN10 | PTP-AN10 / 6.6.89-android15-8 | `6.6.89-android15-8-g9f1d85cc0389-abogki440235034-4k` |
| ROD2-W09 | ROD2-W09 / 6.1.157-android14-11 | `6.1.157-android14-11-g8d63307071ad` |
| ROL-W00 | ROL-W00 / 6.1.157-android14 | `6.1.157-android14-11-g325066eea80d` |
| SER-AN00 | SER-AN00 / AAK-AN00 / 6.6.118-android15-8 | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` |
| VKP-N39 | VKP-N39 / 6.6.118-android15 | `6.6.118-android15-8-gc901ea41aa32-ab15981388-4k` |
| WKL-AN80 | WKL-AN80 / 6.18.21-android17 | `6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k` |
| WKL-N59 | WKL-N59 / 6.18.21-android17 | `6.18.21-android17-5-g52885947a517-ab16374447-4k` |
| YAG-W10 | YAG-W10 / 5.15.180-android13 | `5.15.180-android13-8-g69dabf204ec1` |
| YLP-W00 | g7ae8ec909e03 (offsets-only) | `6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k` |
| — | 5.15.123-android13 | `5.15.123-android13-8-gf1f05f80aabb` |
| — | 6.1.128-android14-11 | `6.1.128-android14-11-g52c266270871` |
| — | 6.1.157-android14 | `6.1.157-android14-11-g8ed20bdebf81` |
| — | 6.1.99-android14 | `6.1.99-android14-11-gd6fcc757629f` |
| — | 6.12.58-g142ddad31e60 (offsets-only) | `6.12.58-android16-6-g142ddad31e60-abogki576095858-4k` |
| — | 6.12.58-g42fcf008ff5c (offsets-only) | `6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k` |
| — | PPG-AN00 / 6.6.89-android15-8 (FW135) | `6.6.89-android15-8-g082e5a98dac1` |
| — | g3306a328b7be (offsets-only) | `6.1.157-android14-11-g3306a328b7be-abogki` |
| — | g40b1fd119d9b (offsets-only) | `6.1.128-android14-11-g40b1fd119d9b-abogki` |
| — | g54d40b4fb287 (offsets-only) | `6.1.99-android14-11-g54d40b4fb287-abogki` |
| — | g5859fbdba8c (offsets-only) | `6.1.99-android14-11-g5859fbdba8c-abogki` |
| — | g6484937db664 (offsets-only) | `6.6.58-android15-8-g6484937db664-abogki` |
| — | g77f76e323a02 (offsets-only) | `6.1.157-android14-11-g77f76e323a02-abogki` |
| — | gcd85666d7884 (offsets-only) | `6.12.23-android16-5-gcd85666d7884-abogki452537391-4k` |
| — | gce84935796c9 (offsets-only) | `6.1.99-android14-11-gce84935796c9-abogki` |
| — | ge9da27488f45 (offsets-only) | `6.1.99-android14-11-ge9da27488f45-abogki` |

> 匹配规则：先按 `release.startsWith(prefix)`，同前缀多条再按 `models` 精确比 `Build.MODEL`。
> 同一个 `release` 下不同 build 必须分开（`k_itimer` 尺寸、`task_struct.cred`、三个 call site 都可能不同）。

## 只有识别、没有偏移的机型

`ConfigGen.KNOWN` 里还列了一批「知道有这台机器、但没有可信偏移」的内核，界面只显示「需标定」，
不会下发 `device.cfg`。用你自己的 `boot.img` 在「标定」页解析一次即可补上。
