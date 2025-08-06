import cv2
import numpy as np
import os
import argparse
import random


# --- 核心水印功能 ---

def embed_watermark(image_path, watermark_path, output_path):
    """
    将一个二值的黑白水印图像嵌入到彩色宿主图像中。
    采用最低有效位（LSB）算法。

    参数:
    image_path (str): 原始宿主图像的路径。
    watermark_path (str): 黑白水印图像的路径。
    output_path (str): 保存嵌入水印后图像的路径。
    """
    try:
        # 1. 读取宿主图像和水印图像
        host_image = cv2.imread(image_path)
        watermark_image = cv2.imread(watermark_path, cv2.IMREAD_GRAYSCALE)

        if host_image is None:
            raise FileNotFoundError(f"无法加载宿主图像: {image_path}")
        if watermark_image is None:
            raise FileNotFoundError(f"无法加载水印图像: {watermark_path}")

        print(f"宿主图像尺寸: {host_image.shape}")
        print(f"水印图像尺寸: {watermark_image.shape}")

        # 2. 检查宿主图像是否有足够空间嵌入水印
        h, w, _ = host_image.shape
        wm_h, wm_w = watermark_image.shape
        if wm_h * wm_w > h * w * 3:
            raise ValueError("错误：水印图像太大，无法嵌入到宿主图像中。")

        # 3. 将水印图像二值化 (0和1)
        # 阈值设为128，大于128的像素为白色(1)，否则为黑色(0)
        _, binary_watermark = cv2.threshold(watermark_image, 128, 1, cv2.THRESH_BINARY)

        # 将二维的水印比特流扁平化为一维数组
        watermark_bits = binary_watermark.flatten()
        watermark_len = len(watermark_bits)

        print(f"成功将水印转换为 {watermark_len} 比特流。")

        # 4. 遍历宿主图像像素，嵌入水印
        bit_index = 0
        embedded_image = host_image.copy()  # 创建副本以进行修改

        for i in range(h):
            for j in range(w):
                # 遍历B, G, R三个颜色通道
                for k in range(3):
                    if bit_index < watermark_len:
                        # 获取当前像素的颜色值
                        pixel_val = embedded_image[i, j, k]

                        # 获取要嵌入的水印比特 (0 或 1)
                        watermark_bit = watermark_bits[bit_index]

                        # 使用位运算修改最低有效位 (LSB)
                        # 如果要嵌入0, 则将最低位置0 (与 ...11111110 AND)
                        # 如果要嵌入1, 则将最低位置1 (与 ...00000001 OR)
                        new_pixel_val = (pixel_val & 0b11111110) | watermark_bit
                        embedded_image[i, j, k] = new_pixel_val

                        bit_index += 1
                    else:
                        break
                if bit_index >= watermark_len:
                    break
            if bit_index >= watermark_len:
                break

        # 5. 保存嵌入水印的图像
        cv2.imwrite(output_path, embedded_image)
        print(f"水印嵌入成功！已保存至: {output_path}")

    except Exception as e:
        print(f"发生错误: {e}")


def extract_watermark(watermarked_path, watermark_dims, output_path):
    """
    从已嵌入水印的图像中提取水印。

    参数:
    watermarked_path (str): 嵌入水印的图像路径。
    watermark_dims (tuple): 一个 (height, width) 元组，指定原始水印的尺寸。
    output_path (str): 保存提取出的水印图像的路径。
    """
    try:
        # 1. 读取带水印的图像
        watermarked_image = cv2.imread(watermarked_path)
        if watermarked_image is None:
            raise FileNotFoundError(f"无法加载带水印的图像: {watermarked_path}")

        wm_h, wm_w = watermark_dims
        num_bits_to_extract = wm_h * wm_w

        print(f"准备从图像中提取 {num_bits_to_extract} 比特...")

        # 2. 提取 LSB 比特
        extracted_bits = []
        h, w, _ = watermarked_image.shape

        for i in range(h):
            for j in range(w):
                for k in range(3):
                    if len(extracted_bits) < num_bits_to_extract:
                        pixel_val = watermarked_image[i, j, k]
                        # 使用位与操作提取最低有效位
                        extracted_bit = pixel_val & 1
                        extracted_bits.append(extracted_bit)
                    else:
                        break
                if len(extracted_bits) >= num_bits_to_extract:
                    break
            if len(extracted_bits) >= num_bits_to_extract:
                break

        # 3. 将比特流重塑为图像
        if len(extracted_bits) < num_bits_to_extract:
            raise ValueError("错误：图像数据不足以提取完整水印。可能是尺寸错误或图像被裁剪。")

        watermark_array = np.array(extracted_bits).reshape((wm_h, wm_w))

        # 将水印数组从 (0, 1) 转换为 (0, 255) 以便显示和保存
        extracted_watermark_image = (watermark_array * 255).astype(np.uint8)

        # 4. 保存提取的水印
        cv2.imwrite(output_path, extracted_watermark_image)
        print(f"水印提取成功！已保存至: {output_path}")

    except Exception as e:
        print(f"发生错误: {e}")


# --- 鲁棒性测试功能 ---

def calculate_similarity(original_wm_path, extracted_wm_path):
    """计算两个水印图像的相似度 (像素匹配率)"""
    original = cv2.imread(original_wm_path, cv2.IMREAD_GRAYSCALE)
    extracted = cv2.imread(extracted_wm_path, cv2.IMREAD_GRAYSCALE)

    if original is None or extracted is None or original.shape != extracted.shape:
        return 0.0

    # 二值化以确保比较的是纯黑白
    _, original_bin = cv2.threshold(original, 128, 255, cv2.THRESH_BINARY)
    _, extracted_bin = cv2.threshold(extracted, 128, 255, cv2.THRESH_BINARY)

    # 计算匹配的像素数
    matching_pixels = np.sum(original_bin == extracted_bin)
    total_pixels = original.size

    similarity = (matching_pixels / total_pixels) * 100
    return similarity


def test_robustness(watermarked_path, original_wm_path, watermark_dims):
    """
    对嵌入水印的图像进行一系列鲁棒性攻击测试。
    """
    print("\n--- 开始鲁棒性测试 ---")

    # 确保测试输出目录存在
    output_dir = "robustness_tests"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. 无攻击（作为基准）
    print("\n[测试 1/6] 无攻击基准测试")
    base_extracted_path = os.path.join(output_dir, "extracted_base.png")
    extract_watermark(watermarked_path, watermark_dims, base_extracted_path)
    sim = calculate_similarity(original_wm_path, base_extracted_path)
    print(f"  > 相似度: {sim:.2f}%")

    # 加载原始带水印图像以进行攻击
    img = cv2.imread(watermarked_path)
    h, w, _ = img.shape

    # 2. 翻转攻击 (水平)
    print("\n[测试 2/6] 水平翻转攻击")
    flipped_img = cv2.flip(img, 1)
    attacked_path = os.path.join(output_dir, "attacked_flip.png")
    extracted_path = os.path.join(output_dir, "extracted_flip.png")
    cv2.imwrite(attacked_path, flipped_img)
    extract_watermark(attacked_path, watermark_dims, extracted_path)
    sim = calculate_similarity(original_wm_path, extracted_path)
    print(f"  > 相似度: {sim:.2f}%")

    # 3. 平移攻击
    print("\n[测试 3/6] 平移攻击")
    tx, ty = 50, 30  # 向右平移50, 向下平移30
    translation_matrix = np.float32([[1, 0, tx], [0, 1, ty]])
    translated_img = cv2.warpAffine(img, translation_matrix, (w, h))
    attacked_path = os.path.join(output_dir, "attacked_translate.png")
    extracted_path = os.path.join(output_dir, "extracted_translate.png")
    cv2.imwrite(attacked_path, translated_img)
    extract_watermark(attacked_path, watermark_dims, extracted_path)
    sim = calculate_similarity(original_wm_path, extracted_path)
    print(f"  > 相似度: {sim:.2f}%")

    # 4. 截取攻击
    print("\n[测试 4/6] 截取攻击")
    # 从左上角截取右下角3/4的区域
    crop_img = img[0:int(h * 0.75), 0:int(w * 0.75)]
    attacked_path = os.path.join(output_dir, "attacked_crop.png")
    extracted_path = os.path.join(output_dir, "extracted_crop.png")
    cv2.imwrite(attacked_path, crop_img)
    # 对于LSB，截取后无法恢复，提取会失败。但我们依然尝试提取以展示效果。
    # 注意：这里会抛出异常，因为图像变小了。
    try:
        extract_watermark(attacked_path, watermark_dims, extracted_path)
        sim = calculate_similarity(original_wm_path, extracted_path)
        print(f"  > 相似度: {sim:.2f}%")
    except ValueError as e:
        print(f"  > 提取失败，符合预期: {e}")
        print(f"  > 相似度: 0.00%")

    # 5. 调整对比度攻击
    print("\n[测试 5/6] 调整对比度攻击")
    alpha = 1.5  # 对比度因子
    beta = 10  # 亮度增益
    contrast_img = cv2.convertScaleAbs(img, alpha=alpha, beta=beta)
    attacked_path = os.path.join(output_dir, "attacked_contrast.png")
    extracted_path = os.path.join(output_dir, "extracted_contrast.png")
    cv2.imwrite(attacked_path, contrast_img)
    extract_watermark(attacked_path, watermark_dims, extracted_path)
    sim = calculate_similarity(original_wm_path, extracted_path)
    print(f"  > 相似度: {sim:.2f}%")

    # 6. JPEG有损压缩攻击
    print("\n[测试 6/6] JPEG 压缩攻击")
    attacked_path = os.path.join(output_dir, "attacked_jpeg.jpg")
    extracted_path = os.path.join(output_dir, "extracted_jpeg.png")
    cv2.imwrite(attacked_path, img, [int(cv2.IMWRITE_JPEG_QUALITY), 85])  # 85%质量
    extract_watermark(attacked_path, watermark_dims, extracted_path)
    sim = calculate_similarity(original_wm_path, extracted_path)
    print(f"  > 相似度: {sim:.2f}%")

    print("\n--- 鲁棒性测试结束 ---")


# --- 主函数与命令行界面 ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LSB图像水印系统，支持嵌入、提取和鲁棒性测试。")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 嵌入命令
    embed_parser = subparsers.add_parser("embed", help="将水印嵌入图像")
    embed_parser.add_argument("-i", "--image", required=True, help="宿主图像文件路径")
    embed_parser.add_argument("-w", "--watermark", required=True, help="水印图像文件路径")
    embed_parser.add_argument("-o", "--output", required=True, help="嵌入水印后的图像输出路径")

    # 提取命令
    extract_parser = subparsers.add_parser("extract", help="从图像中提取水印")
    extract_parser.add_argument("-i", "--image", required=True, help="带水印的图像文件路径")
    extract_parser.add_argument("-o", "--output", required=True, help="提取出的水印图像输出路径")
    extract_parser.add_argument("--height", type=int, required=True, help="原始水印的高度")
    extract_parser.add_argument("--width", type=int, required=True, help="原始水印的宽度")

    # 测试命令
    test_parser = subparsers.add_parser("test", help="对带水印图像进行鲁棒性测试")
    test_parser.add_argument("-i", "--image", required=True, help="已嵌入水印的图像文件路径")
    test_parser.add_argument("-w", "--watermark", required=True, help="原始水印图像文件路径，用于对比")
    test_parser.add_argument("--height", type=int, required=True, help="原始水印的高度")
    test_parser.add_argument("--width", type=int, required=True, help="原始水印的宽度")

    args = parser.parse_args()

    if args.command == "embed":
        embed_watermark(args.image, args.watermark, args.output)
    elif args.command == "extract":
        extract_watermark(args.image, (args.height, args.width), args.output)
    elif args.command == "test":
        test_robustness(args.image, args.watermark, (args.height, args.width))