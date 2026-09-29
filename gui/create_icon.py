from PIL import Image, ImageDraw, ImageFont
import os

def create_icon():
    sizes = [16, 32, 48, 64, 128, 256]
    images = []

    for size in sizes:
        img  = Image.new('RGBA', (size, size),
                         (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Background circle
        draw.ellipse(
            [2, 2, size-2, size-2],
            fill=(10, 15, 26, 255)
        )

        # Border
        draw.ellipse(
            [2, 2, size-2, size-2],
            outline=(0, 212, 255, 255),
            width=max(1, size//16)
        )

        # Q letter
        font_size = int(size * 0.55)
        try:
            font = ImageFont.truetype(
                "arial.ttf", font_size
            )
        except Exception:
            font = ImageFont.load_default()

        bbox = draw.textbbox((0,0), "Q", font=font)
        tw   = bbox[2] - bbox[0]
        th   = bbox[3] - bbox[1]
        x    = (size - tw) // 2
        y    = (size - th) // 2 - size//10

        draw.text(
            (x, y), "Q", font=font,
            fill=(0, 212, 255, 255)
        )
        images.append(img)

    # ICO file save karo
    icon_path = os.path.join(
        os.path.dirname(__file__), "qnids_icon.ico"
    )
    images[0].save(
        icon_path,
        format='ICO',
        sizes=[(s, s) for s in sizes],
        append_images=images[1:]
    )
    print(f"Icon created: {icon_path}")

if __name__ == "__main__":
    create_icon()