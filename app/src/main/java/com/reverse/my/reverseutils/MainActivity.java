package com.reverse.my.reverseutils;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.net.DhcpInfo;
import android.net.wifi.WifiManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("rev");
    }

    private void callSetText(TextView textView) {
        textView.setText("hehe");
    }

    private int testSum(int from, int to) {
        int sum=0;
        for (int i = from; i < to;i++) {
            sum+=i;
        }
        return sum;
    }

    private String getStr() {
        String obj = new String("123");
        if (obj.compareTo("321") > 0) {
            return "333";
        }
        return obj;
    }

    private Object getStr2() {
        return new MainActivity();
    }

    private void test() {
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText("aaa");
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Example of a call to a native method
        TextView tv = (TextView) findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());
        callSetText(tv);
        int s = testSum(1, 10);
        String str = getStr();
        Toast.makeText(this, s+str, Toast.LENGTH_LONG).show();
        ApplicationInfo info = this.getApplicationInfo();
        try {
            WifiManager mgr = (WifiManager) this.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            DhcpInfo d = mgr.getDhcpInfo();
            int g = d.gateway;
            System.out.print(1);
        } catch (Exception ex) {
            // getDhcpInfo() is not documented to require any permissions, but on some devices
            // requires android.permission.ACCESS_WIFI_STATE. Just catch the generic exception
            // here and returning 0. Not logging because this could be noisy.
            ex.printStackTrace();
        }
        System.out.print(1);
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();
}
