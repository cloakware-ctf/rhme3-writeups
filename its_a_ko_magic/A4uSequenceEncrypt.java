/** copyright Irdeto */

import static acquisition2.target.CommandLogging.*;
import static acquisition2.target.ErrorHandling.*;
import static com.riscure.signalanalysis.data.SimpleVerdict.*;
import com.riscure.signalanalysis.acquisition.DataProvider;
import static com.riscure.util.HexUtils.*;
import java.util.concurrent.TimeoutException;
import com.riscure.hardware.raw.RawIODevice;

// GUI parameter libraries
import com.riscure.osgi.annotation.Reference;
import com.riscure.beans.annotation.DisplayName;
import acquisition2.target.BasicSequence;
import acquisition2.generator.RandomDataProviderImpl;
import org.osgi.framework.ServiceReference;
/*
import javax.validation.constraints.DecimalMax;
import javax.validation.constraints.DecimalMin;
import com.riscure.beans.constraints.DecimalStep;
import com.riscure.beans.annotation.Perturbation;
import com.riscure.beans.annotation.Presentation;
import com.riscure.beans.annotation.Unit;
import java.math.BigDecimal;
*/
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.util.Arrays;

// @Service("A4uSequence")
public class A4uSequenceEncrypt extends BasicSequence {
    private DataProvider dp = new RandomDataProviderImpl(0); 
    private A4uSequenceSettings settings = new A4uSequenceSettings();

    private RawIODevice rawIODevice1;

    @Override
    protected void init() {
        // Get all devices from hardware manager
        rawIODevice1 = getRawIODevice(settings.getRawIODevice1());

        // Set default devices
        setDefaultDevice(rawIODevice1);

        // If any error occur the sequence will fail
        onError(FAIL);

        // Open all devices
        open(rawIODevice1);

        //Example properties (change these!)
        //These need to be set BEFORE calling connect();
        setProperty(rawIODevice1, "baudrate", 115200);
        setProperty(rawIODevice1, "dataBits", 8);
        setProperty(rawIODevice1, "parity", "NONE");
        setProperty(rawIODevice1, "stopBits", 1);

        connect(rawIODevice1);
    }

    @Override
    public void run() {

        // Set the default verdict to inconclusive
        verdict(INCONCLUSIVE);

        // Arm the measurement setup
        arm();
        sleep(50);//Post-arming time delay in ms for the scope to get ready

        // From this point forward ignore errors
        onError(FAIL);

        // Set read timeout to 1000 ms
        setDefaultReadTimeout(1000);
        
        //example communication
        // Write byte sequence to default device, also include in perturbation log
        //write(hex("CA FE BA BE 00 00 06"));
        byte[] bytes = dp.getBytes(null,18);
        bytes[0] =(byte)0xAE;
        bytes[17]=(byte)0x0A;
        for (int i=1;i<17;i++) if (bytes[i] == (byte)0x0a) bytes[i] = (byte)0x00;
        
        //soft-trigger the measurement setup
        softTrigger();

        //write(hex("AD 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 0A"));
        write(rawIODevice1, bytes, NO_LOG);

        byte[] response = readAll(rawIODevice1,34,800,0);
        //byte[] response2 = readBytes();

        
        // If data was available
        if (response.length == 34) {
            addDataIn(Arrays.copyOfRange(bytes,1,17));
            addDataOut(Arrays.copyOfRange(response,18,34));
            verdict(NORMAL);
            // Add length to the perturbation log
            appendLog(hex("22"));
        } else {
            byte[] b = new byte[1];
            b[0] = (byte)response.length;
            appendLog(b);
        }
    }

    @Override
    protected void onError(Throwable t) throws RuntimeException {
        if (t instanceof TimeoutException) {
            // Ignore
        } else {
            throw new RuntimeException(t);
        }
    }

    @Override
    public void close() {
        // Close all devices, note that closing does not mean powering down
        close(rawIODevice1);
    }

    @Override
    public A4uSequenceSettings getSettingsBean() {
        return settings;
    }

    @Override
    public void setSettingsBean(Object settings) {
        this.settings = (A4uSequenceSettings) settings;
    }

    public static class A4uSequenceSettings {

        @Reference(RawIODevice.class)
        @DisplayName("Raw I/O Device 1")
        private ServiceReference rawIODevice1;

        public ServiceReference getRawIODevice1() {
            return rawIODevice1;
        }

        public void setRawIODevice1(ServiceReference rawIODevice1) {
            this.rawIODevice1 = rawIODevice1;
        }

        /* Custom parameter examples
        @DisplayName("Perturbation Tab Parameter")
        @Unit("Unit")
        @DecimalMin("0")
        @DecimalMax("10000000")
        @DecimalStep("4")
        @Presentation(slider = false)
        @Perturbation // This makes the parameter shows up in Perturbation tab.

        private BigDecimal perturParam = BigDecimal.valueOf(4);

        public BigDecimal getPerturParam() {
          return perturParam;
        }

        public void setPerturParam(BigDecimal perturParam) {
          BigDecimal old = this.perturParam;
          this.perturParam = perturParam;
          pcs.firePropertyChange("perturParam", old, this.perturParam);
        }

        @DisplayName("Target Tab Parameter")
        @Unit("Unit")
        @DecimalMin("4")
        @DecimalMax("1000000")
        @DecimalStep("4")
        @Presentation(slider = false)

        private BigDecimal targetParam = BigDecimal.valueOf(4);

        public BigDecimal getTargetParam() {
          return targetParam;
        }

        public void setTargetParam(BigDecimal targetParam) {
          BigDecimal old = this.targetParam;
          this.targetParam = targetParam;
          pcs.firePropertyChange("targetParam", old, this.targetParam);
        } 
        */

        /*
         * Property change support
         */
        private PropertyChangeSupport pcs = new PropertyChangeSupport(this);

        public void addPropertyChangeListener(PropertyChangeListener listener) {
            this.pcs.addPropertyChangeListener(listener);
        }

        public void addPropertyChangeListener(String propertyName, PropertyChangeListener listener) {
            this.pcs.addPropertyChangeListener(propertyName, listener);
        }

        public void removePropertyChangeListener(PropertyChangeListener listener) {
            this.pcs.removePropertyChangeListener(listener);
        }

        public void removePropertyChangeListener(String propertyName, PropertyChangeListener listener) {
            this.pcs.removePropertyChangeListener(propertyName, listener);
        }

    }
}
