/**
 *  @file ViewController.m
 *  @brief XNU Image Fuzzer.
 *  @author @h02332 | David Hoyt
 *  @date 29 FEB 2024
 *  @version 1.0.0
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *  @section CHANGES
 *  - 29/02/2024, h02332: Initial commit.
 *
 */

#pragma mark - Headers

/**
@brief Core and external libraries necessary for the fuzzer functionality.

@details This section includes the necessary headers for the Foundation framework, UIKit, Core Graphics,
standard input/output, standard library, memory management, mathematical functions,
Boolean type, floating-point limits, and string functions. These libraries support
image processing, UI interaction, and basic C operations essential for the application.
*/
#import "ViewController.h"

@interface ViewController () <UICollectionViewDataSource, UICollectionViewDelegateFlowLayout>
@property (weak, nonatomic) IBOutlet UICollectionView *collectionView;
@property (strong, nonatomic) NSMutableArray<UIImage *> *fuzzedImages;
@property (strong, nonatomic) NSMutableArray<NSString *> *imagePaths; // Keep track of image paths for debugging
@end

@implementation ViewController

#pragma mark - View Lifecycle

- (void)viewDidLoad {
    [super viewDidLoad];
    self.collectionView.dataSource = self;
    self.collectionView.delegate = self;
    self.collectionView.backgroundColor = [UIColor yellowColor]; // Ensure visibility of collectionView
    self.fuzzedImages = [NSMutableArray array];
    self.imagePaths = [NSMutableArray array];
    [self loadFuzzedImagesFromDocumentsDirectory];
}

#pragma mark - Loading Images

- (void)loadFuzzedImagesFromDocumentsDirectory {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *documentsDirectoryPath = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    
    NSError *error = nil;
    NSArray *directoryContents = [fileManager contentsOfDirectoryAtPath:documentsDirectoryPath error:&error];
    
    if (!error) {
        NSLog(@"Directory contents at %@: %@", documentsDirectoryPath, directoryContents);
        
        for (NSString *item in directoryContents) {
            NSString *filePath = [documentsDirectoryPath stringByAppendingPathComponent:item];
            if ([item.pathExtension isEqualToString:@"png"] || [item.pathExtension isEqualToString:@"jpg"] || [item.pathExtension isEqualToString:@"jpeg"]) {
                UIImage *image = [UIImage imageWithContentsOfFile:filePath];
                if (image) {
                    [self.fuzzedImages addObject:image];
                    [self.imagePaths addObject:filePath]; // Store the image path for debugging
                    NSLog(@"Loaded image: %@", filePath); // Log each image file path as it's loaded
                }
            }
        }
    } else {
        NSLog(@"Error listing documents directory: %@", error.localizedDescription);
    }
    
    NSLog(@"Loaded %lu images in total", (unsigned long)[self.fuzzedImages count]);
    
    // Ensure UI updates are performed on the main thread
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.collectionView reloadData];
    });
}

#pragma mark - UICollectionViewDataSource

- (NSInteger)collectionView:(UICollectionView *)collectionView numberOfItemsInSection:(NSInteger)section {
    NSLog(@"numberOfItemsInSection: %lu", (unsigned long)self.fuzzedImages.count);
    return self.fuzzedImages.count;
}

- (UICollectionViewCell *)collectionView:(UICollectionView *)collectionView cellForItemAtIndexPath:(NSIndexPath *)indexPath {
    NSString *cellIdentifier = [self determineCellIdentifierForIndexPath:indexPath];
    
    UICollectionViewCell *cell = [collectionView dequeueReusableCellWithReuseIdentifier:cellIdentifier forIndexPath:indexPath];
    
    UIImageView *imageView = (UIImageView *)[cell.contentView viewWithTag:100];
    if (!imageView) {
        imageView = [[UIImageView alloc] initWithFrame:cell.contentView.bounds];
        imageView.tag = 100;
        imageView.contentMode = UIViewContentModeScaleAspectFit;
        [cell.contentView addSubview:imageView];
    }
    
    imageView.image = self.fuzzedImages[indexPath.row];
    NSString *loadedImagePath = self.imagePaths[indexPath.row];
    
    NSLog(@"Displaying image from %@ in cell %@ at IndexPath: %@", loadedImagePath, cellIdentifier, indexPath);
    cell.backgroundColor = [UIColor blueColor];
    imageView.backgroundColor = [UIColor redColor];
    
    return cell;
}

- (NSString *)determineCellIdentifierForIndexPath:(NSIndexPath *)indexPath {
    switch (indexPath.row % 3) {
        case 0: return @"ImageCell";
        case 1: return @"ImageCell2";
        case 2: return @"ImageCell3";
        default: return @"ImageCell";
    }
}

#pragma mark - UICollectionViewDelegateFlowLayout

- (CGSize)collectionView:(UICollectionView *)collectionView layout:(UICollectionViewLayout *)collectionViewLayout sizeForItemAtIndexPath:(NSIndexPath *)indexPath {
    return CGSizeMake(100, 100);
}

@end

