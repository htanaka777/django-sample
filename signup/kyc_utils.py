import io
from PIL import Image, ImageDraw, ImageFont
from django.conf import settings
from django.utils import timezone


def add_watermark(image_bytes: bytes, user_id: str) -> tuple[bytes, str, str]:
    """
    透かしを合成して bytes を返す
    戻り値: (watermarked_bytes, mime_type, file_ext)

    本番・デモ共通のコード。Vault の有無に関係なく動作する。
    """
    # まず画像を開く
    img = Image.open(io.BytesIO(image_bytes))

    # PNG の透過なども扱いやすいよう RGBA へ変換
    if img.mode != "RGBA":
        img = img.convert("RGBA")

    # 透かし文字（JST 表示）
    ts = timezone.localtime(timezone.now()).strftime("%Y-%m-%d %H:%M:%S %Z")
    text = f"{user_id}  {ts}"

    # 描画用レイヤ
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    # フォント: OS 標準がない場合はデフォルトにフォールバック
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", settings.KYC_WATERMARK_FONT_SIZE)
    except Exception:
        font = ImageFont.load_default()

    # 位置（右下）
    margin = getattr(settings, "KYC_WATERMARK_MARGIN_PX", 16)
    bbox = draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]
    x = max(margin, img.size[0] - text_w - margin)
    y = max(margin, img.size[1] - text_h - margin)

    # 半透明（白文字 + 黒影）
    draw.text((x + 1, y + 1), text, font=font, fill=(0, 0, 0, 120))
    draw.text((x, y),         text, font=font, fill=(255, 255, 255, 160))

    merged = Image.alpha_composite(img, overlay)

    # 出力は JPEG に統一
    out = merged.convert("RGB")
    buf = io.BytesIO()
    out.save(buf, format="JPEG", quality=90, optimize=True)
    return buf.getvalue(), "image/jpeg", "jpg"
