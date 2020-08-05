#import "ViewController.h"
#include <stdio.h>
#include "async_wake.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  // Do any additional setup after loading the view, typically from a nib.
    self.tfp.text = [NSString stringWithFormat:@"tfp: %x", go()];
}


- (void)didReceiveMemoryWarning {
  printf("******* received memory warning! ***********\n");
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}


@end
